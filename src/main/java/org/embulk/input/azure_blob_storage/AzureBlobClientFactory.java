package org.embulk.input.azure_blob_storage;

import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.OperationContext;
import com.microsoft.azure.storage.SendingRequestEvent;
import com.microsoft.azure.storage.StorageCredentialsSharedAccessSignature;
import com.microsoft.azure.storage.StorageCredentialsToken;
import com.microsoft.azure.storage.StorageEvent;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import org.embulk.config.ConfigException;
import org.embulk.input.azure_blob_storage.AzureBlobStorageFileInputPlugin.PluginTask;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.util.Optional;

/**
 * Creates the Azure Blob Storage client and the per-request context for the configured auth method.
 *
 * - account_key: the same connection string as before, so existing configurations behave exactly as they did.
 * - sas_token: the SAS token is sent as the query string of each request.
 * - service_principal: an access token from Microsoft Entra ID is sent as a bearer token. The token is refreshed
 *   right before a request is signed when it is about to expire, so long transfers don't fail halfway.
 */
public class AzureBlobClientFactory
{
    private final String accountName;
    private final AuthMethod authMethod;
    private final ProxyTask proxyTask;
    private final String accountKey;
    private final String sasToken;
    private final ServicePrincipalTokenProvider tokenProvider;
    private StorageCredentialsToken tokenCredentials;

    public AzureBlobClientFactory(PluginTask task)
    {
        this(task, task.getAuthMethod() == AuthMethod.SERVICE_PRINCIPAL
                ? new ServicePrincipalTokenProvider(
                        required(task.getTenantId(), "tenant_id"),
                        required(task.getClientId(), "client_id"),
                        required(task.getClientSecret(), "client_secret"),
                        task.getProxy().orElse(null))
                : null);
    }

    AzureBlobClientFactory(PluginTask task, ServicePrincipalTokenProvider tokenProvider)
    {
        this.accountName = task.getAccountName();
        this.authMethod = task.getAuthMethod();
        this.proxyTask = task.getProxy().orElse(null);
        this.accountKey = authMethod == AuthMethod.ACCOUNT_KEY ? required(task.getAccountKey(), "account_key") : null;
        this.sasToken = authMethod == AuthMethod.SAS_TOKEN ? normalizeSasToken(required(task.getSasToken(), "sas_token")) : null;
        this.tokenProvider = tokenProvider;
    }

    /**
     * Checks that the options needed by the auth method are set, before any request is sent.
     */
    public static void validate(PluginTask task)
    {
        new AzureBlobClientFactory(task, null);
        if (task.getAuthMethod() == AuthMethod.SERVICE_PRINCIPAL) {
            required(task.getTenantId(), "tenant_id");
            required(task.getClientId(), "client_id");
            required(task.getClientSecret(), "client_secret");
        }
    }

    public CloudBlobClient createClient()
    {
        switch (authMethod) {
            case SERVICE_PRINCIPAL:
                return new CloudBlobClient(blobEndpoint(), tokenCredentials());
            case SAS_TOKEN:
                return new CloudBlobClient(blobEndpoint(), new StorageCredentialsSharedAccessSignature(sasToken));
            default:
                return newAccountKeyClient();
        }
    }

    /**
     * Returns a new context to pass to requests. It is null when neither a proxy nor token refreshing is needed,
     * which is the same as before this class was added. The SDK keeps the result of every request in the context,
     * so create a new one for each group of requests instead of sharing one for a whole listing.
     */
    public OperationContext createOperationContext()
    {
        OperationContext op = ProxyTask.toOperationContext(proxyTask);
        if (op != null && authMethod == AuthMethod.SAS_TOKEN) {
            // The SDK logs each request URL at INFO when logging is enabled, and the URL contains the SAS signature.
            op.setLoggingEnabled(false);
        }
        if (authMethod != AuthMethod.SERVICE_PRINCIPAL) {
            return op;
        }
        if (op == null) {
            op = new OperationContext();
        }
        final StorageCredentialsToken credentials = tokenCredentials();
        // Fired right before the request is signed, so the refreshed token is the one that is sent.
        op.getSendingRequestEventHandler().addListener(new StorageEvent<SendingRequestEvent>() {
            @Override
            public void eventOccurred(SendingRequestEvent event)
            {
                credentials.updateToken(tokenProvider.getToken());
            }
        });
        return op;
    }

    private synchronized StorageCredentialsToken tokenCredentials()
    {
        if (tokenCredentials == null) {
            tokenCredentials = new StorageCredentialsToken(accountName, tokenProvider.getToken());
        }
        return tokenCredentials;
    }

    private CloudBlobClient newAccountKeyClient()
    {
        String connectionString = "DefaultEndpointsProtocol=https;" +
                "AccountName=" + accountName + ";" +
                "AccountKey=" + accountKey;

        CloudStorageAccount account;
        try {
            account = CloudStorageAccount.parse(connectionString);
        }
        catch (InvalidKeyException | URISyntaxException ex) {
            throw new ConfigException(ex);
        }
        return account.createCloudBlobClient();
    }

    URI blobEndpoint()
    {
        try {
            return new URI("https://" + accountName + ".blob.core.windows.net");
        }
        catch (URISyntaxException ex) {
            throw new ConfigException("Invalid 'account_name': " + accountName, ex);
        }
    }

    // The Azure portal shows a SAS token with a leading "?", which the SDK does not accept.
    static String normalizeSasToken(String sasToken)
    {
        String token = sasToken.trim();
        return token.startsWith("?") ? token.substring(1) : token;
    }

    private static String required(Optional<String> value, String name)
    {
        if (!value.isPresent() || value.get().trim().isEmpty()) {
            throw new ConfigException("'" + name + "' is required for this 'auth_method'.");
        }
        return value.get();
    }
}
