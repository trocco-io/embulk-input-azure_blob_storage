package org.embulk.input.azure_blob_storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.embulk.config.ConfigException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.function.LongConsumer;
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
    // Used only when the response has no expires_in.
    static final long DEFAULT_EXPIRES_IN_SECONDS = 3600L;
    // Attempts for errors that may go away on retry (network errors, 429 and 5xx).
    static final int MAX_ATTEMPTS = 3;
    // After a failure, don't ask Entra ID again for this long: return the current token while it is valid, or the same
    // error. Without it, every request of every task sharing this provider would run all the attempts again while
    // holding the lock, which nearly stops the transfer (or makes it look hung) while Entra ID is unavailable. Kept
    // short, so that the plugin's retries with a small max_connection_retry still reach Entra ID again.
    static final long REFRESH_RETRY_INTERVAL_MILLIS = 10 * 1000L;
    private static final long RETRY_WAIT_MILLIS = 1000L;
    private static final int TIMEOUT_MILLIS = 30 * 1000;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger log = LoggerFactory.getLogger(ServicePrincipalTokenProvider.class);

    private final String authorityHost;
    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final Proxy proxy;
    private final LongSupplier clock;
    private final LongConsumer sleeper;

    private String accessToken;
    private long expiresAtMillis;
    // The error of the last failed request for a token and when it failed, or null after a successful one
    private RuntimeException lastFailure;
    private long lastFailedAtMillis;

    public ServicePrincipalTokenProvider(String tenantId, String clientId, String clientSecret, ProxyTask proxyTask)
    {
        this(DEFAULT_AUTHORITY_HOST, tenantId, clientId, clientSecret, proxyTask, System::currentTimeMillis,
                ServicePrincipalTokenProvider::sleep);
    }

    ServicePrincipalTokenProvider(String authorityHost, String tenantId, String clientId, String clientSecret,
                                  ProxyTask proxyTask, LongSupplier clock, LongConsumer sleeper)
    {
        this.authorityHost = authorityHost;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.proxy = ProxyTask.toProxy(proxyTask);
        this.clock = clock;
        this.sleeper = sleeper;
        setProxyAuthenticator(proxyTask);
    }

    /**
     * Returns a valid access token, getting a new one when there is none yet or the current one is about to expire.
     * If getting a new one fails while the current one is still valid, the current one is returned, so a temporary
     * error of Entra ID does not stop a transfer. After a failure, Entra ID is not asked again for
     * REFRESH_RETRY_INTERVAL_MILLIS: the current token is returned while it is valid, or else the same error is thrown.
     * Listing and reading are retried with backoff (max_connection_retry), so a retry after that interval asks Entra ID
     * again.
     */
    public synchronized String getToken()
    {
        long now = clock.getAsLong();
        if (accessToken != null && now < expiresAtMillis - REFRESH_MARGIN_MILLIS) {
            return accessToken;
        }
        if (lastFailure != null && now < lastFailedAtMillis + REFRESH_RETRY_INTERVAL_MILLIS) {
            if (hasValidToken(now)) {
                return accessToken;
            }
            throw lastFailure;
        }
        try {
            fetchToken();
            lastFailure = null;
        }
        catch (TokenRequestException | ConfigException ex) {
            lastFailure = ex;
            lastFailedAtMillis = clock.getAsLong();
            // The attempts may have taken a while, so check the token at the time they ended
            if (hasValidToken(lastFailedAtMillis)) {
                log.warn("Failed to refresh the access token. Keep using the current token until it expires: {}", ex.getMessage());
                return accessToken;
            }
            throw ex;
        }
        return accessToken;
    }

    private boolean hasValidToken(long now)
    {
        return accessToken != null && now < expiresAtMillis;
    }

    private void fetchToken()
    {
        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            if (attempt > 1) {
                sleeper.accept(RETRY_WAIT_MILLIS * (1L << (attempt - 2)));
            }
            try {
                requestToken();
                return;
            }
            catch (RetryableTokenException ex) {
                lastError = ex;
                log.warn("Failed to get an access token from Microsoft Entra ID (attempt {}/{}): {}", attempt, MAX_ATTEMPTS, ex.getMessage());
            }
        }
        throw lastError;
    }

    private void requestToken()
    {
        long requestedAt = clock.getAsLong();
        HttpURLConnection connection = null;
        try {
            URL url = new URL(authorityHost + "/" + URLEncoder.encode(tenantId, "UTF-8") + "/oauth2/v2.0/token");
            connection = (HttpURLConnection) (proxy == null ? url.openConnection() : url.openConnection(proxy));
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(TIMEOUT_MILLIS);
            connection.setReadTimeout(TIMEOUT_MILLIS);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream out = connection.getOutputStream()) {
                out.write(requestBody().getBytes(StandardCharsets.UTF_8));
            }

            int status = connection.getResponseCode();
            JsonNode json = parseJson(readBody(status < 400 ? connection.getInputStream() : connection.getErrorStream()));
            if (status == 200 && json.hasNonNull("access_token")) {
                accessToken = json.get("access_token").asText();
                expiresAtMillis = requestedAt + expiresInSeconds(json) * 1000L;
                return;
            }
            // Keep only the error code and its description. They don't contain the client secret.
            String detail = String.format("status: %d, error: %s, description: %s",
                    status, json.path("error").asText(""), json.path("error_description").asText(""));
            if (status == 429 || status >= 500) {
                throw new RetryableTokenException("Microsoft Entra ID returned a temporary error (" + detail + ")", null);
            }
            if (status == 200) {
                throw new TokenRequestException("The response for an access token has no access_token (" + detail + "). "
                        + "Check that nothing between this host and Microsoft Entra ID (e.g. a proxy) changes the response.", null);
            }
            if (!json.hasNonNull("error")) {
                // Not an error of Entra ID (it always has "error"), e.g. an error page of a proxy or a gateway on the way
                throw new TokenRequestException("Failed to get an access token from Microsoft Entra ID (" + detail
                        + "). The response was not from Microsoft Entra ID; check the proxy settings.", null);
            }
            if (status == 400 || status == 401) {
                throw new ConfigException("Failed to get an access token from Microsoft Entra ID (" + detail + "). "
                        + "Check the tenant ID, client ID and client secret.");
            }
            throw new TokenRequestException("Failed to get an access token from Microsoft Entra ID (" + detail + ").", null);
        }
        catch (IOException ex) {
            throw new RetryableTokenException("Failed to get an access token from Microsoft Entra ID: " + ex.getMessage(), ex);
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

    // An error page from a proxy or gateway may not be JSON. Treat it as empty, so the status is still reported.
    private static JsonNode parseJson(String body)
    {
        if (body.isEmpty()) {
            return MAPPER.createObjectNode();
        }
        try {
            return MAPPER.readTree(body);
        }
        catch (IOException ex) {
            return MAPPER.createObjectNode();
        }
    }

    // A lifetime shorter than the refresh margin is kept as is: the token is then fetched again for each request.
    private static long expiresInSeconds(JsonNode json)
    {
        long expiresIn = json.path("expires_in").asLong(0);
        if (expiresIn <= 0) {
            log.warn("The access token response has no expires_in. Assume the token is valid for {} seconds.", DEFAULT_EXPIRES_IN_SECONDS);
            return DEFAULT_EXPIRES_IN_SECONDS;
        }
        return expiresIn;
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

    // For HTTPS through an HTTP proxy, Java opens a tunnel with CONNECT first and does not send request headers set
    // by the caller with it. The proxy credentials have to be given through an Authenticator, as the Azure SDK does.
    private static void setProxyAuthenticator(ProxyTask proxyTask)
    {
        if (proxyTask == null || !proxyTask.getUser().isPresent()) {
            return;
        }
        // Basic authentication for the tunnel is disabled by default since Java 8u111. This is read only once, when
        // the JVM's HTTP client is first loaded, so it has an effect only before the first HTTP connection.
        // transaction() also sets it at the start when a proxy is configured.
        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        final String user = proxyTask.getUser().get();
        final char[] password = proxyTask.getPassword().orElse("").toCharArray();
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication()
            {
                if (getRequestorType() == RequestorType.PROXY) {
                    return new PasswordAuthentication(user, password);
                }
                return null;
            }
        });
    }

    private static void sleep(long millis)
    {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(ex);
        }
    }

    // A failure to get a token that is not a configuration error (those are ConfigException).
    static class TokenRequestException
            extends RuntimeException
    {
        TokenRequestException(String message, Throwable cause)
        {
            super(message, cause);
        }
    }

    // A failure that may go away on retry (network error, 429 or 5xx).
    static class RetryableTokenException
            extends TokenRequestException
    {
        RetryableTokenException(String message, Throwable cause)
        {
            super(message, cause);
        }
    }
}
