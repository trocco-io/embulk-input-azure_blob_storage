package org.embulk.input.azure_blob_storage;

import com.sun.net.httpserver.HttpServer;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.junit.Rule;
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
import java.io.BufferedReader;
import java.net.Authenticator;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestServicePrincipalTokenProvider
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    private HttpServer server;
    // Responses to return in order: "status|body". After they run out, a valid token is returned.
    private final List<String> queuedResponses = new ArrayList<>();
    private final List<Long> sleeps = new ArrayList<>();
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
            int status = responseStatus;
            String body = responseBody != null ? responseBody
                    : "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"token-" + count + "\"}";
            synchronized (queuedResponses) {
                if (!queuedResponses.isEmpty()) {
                    String[] response = queuedResponses.remove(0).split("\\|", 2);
                    status = Integer.parseInt(response[0]);
                    body = response[1];
                }
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
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
        // The proxy test installs a JVM-wide Authenticator.
        Authenticator.setDefault(null);
    }

    private ServicePrincipalTokenProvider provider()
    {
        String authorityHost = "http://127.0.0.1:" + server.getAddress().getPort();
        return new ServicePrincipalTokenProvider(authorityHost, "my-tenant", "my-client", "my secret&", null, now::get, sleeps::add);
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
    public void testWrongCredentialsAreNotRetried()
    {
        responseStatus = 401;
        responseBody = "{\"error\":\"invalid_client\"}";

        assertThrows(ConfigException.class, () -> provider().getToken());
        assertEquals(1, requestCount.get());
    }

    @Test
    public void testTemporaryErrorsAreRetried()
    {
        queuedResponses.add("503|");
        queuedResponses.add("429|{\"error\":\"temporarily_unavailable\"}");

        assertEquals("token-3", provider().getToken());
        assertEquals(3, requestCount.get());
        assertEquals(2, sleeps.size());
    }

    @Test
    public void testTemporaryErrorAfterAllAttemptsKeepsStatus()
    {
        responseStatus = 503;
        responseBody = "<html>Service Unavailable</html>";

        RuntimeException ex = assertThrows(RuntimeException.class, () -> provider().getToken());
        assertFalse(ex instanceof ConfigException);
        assertTrue(ex.getMessage().contains("status: 503"));
        assertEquals(ServicePrincipalTokenProvider.MAX_ATTEMPTS, requestCount.get());
    }

    @Test
    public void testKeepsCurrentTokenWhenRefreshFailsBeforeExpiry()
    {
        ServicePrincipalTokenProvider provider = provider();
        assertEquals("token-1", provider.getToken());

        // Within the refresh margin, but the token has not expired yet.
        now.addAndGet(3600_000L - ServicePrincipalTokenProvider.REFRESH_MARGIN_MILLIS + 1);
        responseStatus = 503;
        responseBody = "";
        assertEquals("token-1", provider.getToken());

        // Once it has expired, the error is reported.
        now.addAndGet(ServicePrincipalTokenProvider.REFRESH_MARGIN_MILLIS);
        assertThrows(RuntimeException.class, provider::getToken);
    }

    @Test
    public void testMissingExpiresInFallsBackToDefault()
    {
        responseBody = "{\"access_token\":\"no-expiry\"}";
        ServicePrincipalTokenProvider provider = provider();
        assertEquals("no-expiry", provider.getToken());

        now.addAndGet(60_000L);
        assertEquals("no-expiry", provider.getToken());
        assertEquals(1, requestCount.get());
    }

    // For HTTPS, Java opens a tunnel with CONNECT. The proxy credentials have to be sent with it.
    @Test
    public void testSendsProxyCredentialsWhenOpeningTunnel() throws Exception
    {
        try (ServerSocket proxyServer = new ServerSocket(0)) {
            List<String> connectRequests = new ArrayList<>();
            Thread proxy = new Thread(() -> {
                try {
                    // First CONNECT: ask for credentials. Later ones: record them and refuse, until the socket is closed.
                    for (int i = 0; !proxyServer.isClosed(); i++) {
                        try (Socket socket = proxyServer.accept()) {
                            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                            StringBuilder request = new StringBuilder();
                            String line;
                            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                                request.append(line).append("\n");
                            }
                            connectRequests.add(request.toString());
                            String response = i == 0
                                    ? "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n"
                                    : "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                            socket.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
                            socket.getOutputStream().flush();
                        }
                    }
                }
                catch (IOException ignored) {
                    // The test asserts on what was recorded.
                }
            });
            proxy.start();

            ConfigSource proxyConfig = runtime.getExec().newConfigSource()
                    .set("type", "http").set("host", "127.0.0.1").set("port", proxyServer.getLocalPort())
                    .set("user", "proxy-user").set("password", "proxy-pass");
            ProxyTask proxyTask = AzureBlobStorageFileInputPlugin.CONFIG_MAPPER.map(proxyConfig, ProxyTask.class);
            ServicePrincipalTokenProvider provider = new ServicePrincipalTokenProvider(
                    "https://login.example.com", "t", "c", "s", proxyTask, now::get, sleeps::add);

            assertThrows(RuntimeException.class, provider::getToken);
            proxyServer.close();
            proxy.join(10_000L);

            assertTrue(connectRequests.toString(), connectRequests.get(0).startsWith("CONNECT login.example.com:443"));
            // Java writes the header name as "Proxy-authorization"; header names are case-insensitive.
            String expected = "proxy-authorization: basic "
                    + Base64.getEncoder().encodeToString("proxy-user:proxy-pass".getBytes(StandardCharsets.UTF_8)).toLowerCase();
            assertTrue(connectRequests.toString(), connectRequests.size() >= 2);
            assertTrue(connectRequests.toString(), connectRequests.get(1).toLowerCase().contains(expected));
        }
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
