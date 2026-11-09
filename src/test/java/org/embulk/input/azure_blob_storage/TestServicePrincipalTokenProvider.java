package org.embulk.input.azure_blob_storage;

import com.sun.net.httpserver.HttpServer;
import org.embulk.config.ConfigException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestServicePrincipalTokenProvider
{
    private HttpServer server;
    private final List<String> requestPaths = new ArrayList<>();
    private final List<String> requestBodies = new ArrayList<>();
    private final AtomicInteger requestCount = new AtomicInteger();
    private volatile int responseStatus = 200;
    private volatile String responseBody;
    private final AtomicLong now = new AtomicLong(1_000_000L);

    @Before
    public void startServer() throws IOException
    {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            int count = requestCount.incrementAndGet();
            requestPaths.add(exchange.getRequestURI().getPath());
            requestBodies.add(readAll(exchange.getRequestBody()));
            String body = responseBody != null ? responseBody
                    : "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"token-" + count + "\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(responseStatus, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @After
    public void stopServer()
    {
        server.stop(0);
    }

    private ServicePrincipalTokenProvider provider()
    {
        String authorityHost = "http://127.0.0.1:" + server.getAddress().getPort();
        return new ServicePrincipalTokenProvider(authorityHost, "my-tenant", "my-client", "my secret&", null, now::get);
    }

    @Test
    public void testRequestsTokenWithClientCredentials()
    {
        assertEquals("token-1", provider().getToken());
        assertEquals("/my-tenant/oauth2/v2.0/token", requestPaths.get(0));
        String body = requestBodies.get(0);
        assertTrue(body.contains("grant_type=client_credentials"));
        assertTrue(body.contains("client_id=my-client"));
        assertTrue(body.contains("client_secret=my+secret%26"));
        assertTrue(body.contains("scope=https%3A%2F%2Fstorage.azure.com%2F.default"));
    }

    @Test
    public void testReusesTokenUntilShortlyBeforeExpiry()
    {
        ServicePrincipalTokenProvider provider = provider();
        assertEquals("token-1", provider.getToken());

        // Still valid for more than the refresh margin: no new request.
        now.addAndGet(3600_000L - ServicePrincipalTokenProvider.REFRESH_MARGIN_MILLIS - 1);
        assertEquals("token-1", provider.getToken());
        assertEquals(1, requestCount.get());

        // Within the refresh margin: get a new token.
        now.addAndGet(2);
        assertEquals("token-2", provider.getToken());
        assertEquals(2, requestCount.get());
    }

    @Test
    public void testErrorMessageHasErrorCodeButNotSecret()
    {
        responseStatus = 401;
        responseBody = "{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client secret provided.\"}";

        ConfigException ex = assertThrows(ConfigException.class, () -> provider().getToken());
        assertTrue(ex.getMessage().contains("status: 401"));
        assertTrue(ex.getMessage().contains("invalid_client"));
        assertTrue(ex.getMessage().contains("AADSTS7000215"));
        assertFalse(ex.getMessage().contains("my secret"));
    }

    @Test
    public void testErrorWithoutBody()
    {
        responseStatus = 503;
        responseBody = "";

        ConfigException ex = assertThrows(ConfigException.class, () -> provider().getToken());
        assertTrue(ex.getMessage().contains("status: 503"));
    }

    private static String readAll(InputStream in) throws IOException
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}
