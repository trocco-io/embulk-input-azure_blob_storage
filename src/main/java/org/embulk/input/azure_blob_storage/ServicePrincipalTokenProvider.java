package org.embulk.input.azure_blob_storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.embulk.config.ConfigException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.LongSupplier;

/**
 * Gets and caches an access token for Azure Storage from Microsoft Entra ID with the client credentials flow
 * (service principal with a client secret).
 *
 * The token is refreshed shortly before it expires, so long transfers keep working. The token endpoint is called
 * directly instead of through azure-identity, because azure-identity conflicts with the old dependencies
 * (azure-storage 8.x, Jackson 2.6) that this plugin has to keep.
 */
public class ServicePrincipalTokenProvider
{
    static final String DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com";
    static final String STORAGE_SCOPE = "https://storage.azure.com/.default";
    // Refresh the token this long before it expires, so a request never goes out with a token about to expire.
    static final long REFRESH_MARGIN_MILLIS = 5 * 60 * 1000L;
    private static final int TIMEOUT_MILLIS = 30 * 1000;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String authorityHost;
    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final Proxy proxy;
    private final String proxyAuthorization;
    private final LongSupplier clock;

    private String accessToken;
    private long expiresAtMillis;

    public ServicePrincipalTokenProvider(String tenantId, String clientId, String clientSecret, ProxyTask proxyTask)
    {
        this(DEFAULT_AUTHORITY_HOST, tenantId, clientId, clientSecret, proxyTask, System::currentTimeMillis);
    }

    ServicePrincipalTokenProvider(String authorityHost, String tenantId, String clientId, String clientSecret,
                                  ProxyTask proxyTask, LongSupplier clock)
    {
        this.authorityHost = authorityHost;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.proxy = ProxyTask.toProxy(proxyTask);
        this.proxyAuthorization = toProxyAuthorization(proxyTask);
        this.clock = clock;
    }

    /**
     * Returns a valid access token, getting a new one when there is none yet or the current one is about to expire.
     */
    public synchronized String getToken()
    {
        if (accessToken == null || clock.getAsLong() >= expiresAtMillis - REFRESH_MARGIN_MILLIS) {
            fetchToken();
        }
        return accessToken;
    }

    private void fetchToken()
    {
        long requestedAt = clock.getAsLong();
        HttpURLConnection connection = null;
        try {
            URL url = new URL(authorityHost + "/" + URLEncoder.encode(tenantId, "UTF-8") + "/oauth2/v2.0/token");
            connection = (HttpURLConnection) (proxy == null ? url.openConnection() : url.openConnection(proxy));
            if (proxyAuthorization != null) {
                connection.setRequestProperty("Proxy-Authorization", proxyAuthorization);
            }
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(TIMEOUT_MILLIS);
            connection.setReadTimeout(TIMEOUT_MILLIS);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream out = connection.getOutputStream()) {
                out.write(requestBody().getBytes(StandardCharsets.UTF_8));
            }

            int status = connection.getResponseCode();
            String body = readBody(status < 400 ? connection.getInputStream() : connection.getErrorStream());
            JsonNode json = body.isEmpty() ? MAPPER.createObjectNode() : MAPPER.readTree(body);
            if (status != 200 || !json.hasNonNull("access_token")) {
                // Keep only the error code and its description. They don't contain the client secret.
                throw new ConfigException(String.format(
                        "Failed to get an access token from Microsoft Entra ID (status: %d, error: %s, description: %s). "
                                + "Check the tenant ID, client ID and client secret.",
                        status, json.path("error").asText(""), json.path("error_description").asText("")));
            }
            accessToken = json.get("access_token").asText();
            expiresAtMillis = requestedAt + json.path("expires_in").asLong(0) * 1000L;
        }
        catch (IOException ex) {
            throw new RuntimeException("Failed to get an access token from Microsoft Entra ID: " + ex.getMessage(), ex);
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String requestBody() throws UnsupportedEncodingException
    {
        return "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, "UTF-8")
                + "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8")
                + "&scope=" + URLEncoder.encode(STORAGE_SCOPE, "UTF-8");
    }

    private static String readBody(InputStream in) throws IOException
    {
        if (in == null) {
            return "";
        }
        try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static String toProxyAuthorization(ProxyTask proxyTask)
    {
        if (proxyTask == null || !proxyTask.getUser().isPresent()) {
            return null;
        }
        String credentials = proxyTask.getUser().get() + ":" + proxyTask.getPassword().orElse("");
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}
