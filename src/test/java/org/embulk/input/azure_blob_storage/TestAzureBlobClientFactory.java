package org.embulk.input.azure_blob_storage;

import com.microsoft.azure.storage.OperationContext;
import com.microsoft.azure.storage.SendingRequestEvent;
import com.microsoft.azure.storage.StorageCredentialsAccountAndKey;
import com.microsoft.azure.storage.StorageCredentialsSharedAccessSignature;
import com.microsoft.azure.storage.StorageCredentialsToken;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.input.azure_blob_storage.AzureBlobStorageFileInputPlugin.PluginTask;
import org.junit.Rule;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.embulk.input.azure_blob_storage.AzureBlobStorageFileInputPlugin.CONFIG_MAPPER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TestAzureBlobClientFactory
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    private ConfigSource baseConfig()
    {
        return runtime.getExec().newConfigSource()
                .set("account_name", "myaccount")
                .set("container", "my-container")
                .set("path_prefix", "data/");
    }

    private PluginTask task(ConfigSource config)
    {
        return CONFIG_MAPPER.map(config, PluginTask.class);
    }

    @Test
    public void testAccountKeyIsTheDefaultAndKeepsTheConnectionString()
    {
        // A valid base64 key, as the connection string parser checks the format.
        PluginTask task = task(baseConfig().set("account_key", "a2V5"));
        assertEquals(AuthMethod.ACCOUNT_KEY, task.getAuthMethod());

        AzureBlobClientFactory factory = new AzureBlobClientFactory(task);
        CloudBlobClient client = factory.createClient();
        assertTrue(client.getCredentials() instanceof StorageCredentialsAccountAndKey);
        assertEquals("https://myaccount.blob.core.windows.net", client.getEndpoint().toString());
        // No proxy and no token: no context, same as before.
        assertNull(factory.createOperationContext());
    }

    @Test
    public void testSasTokenRemovesLeadingQuestionMark()
    {
        PluginTask task = task(baseConfig().set("auth_method", "sas_token").set("sas_token", " ?sv=2022-11-02&sig=abc "));

        CloudBlobClient client = new AzureBlobClientFactory(task).createClient();
        assertTrue(client.getCredentials() instanceof StorageCredentialsSharedAccessSignature);
        assertEquals("sv=2022-11-02&sig=abc", ((StorageCredentialsSharedAccessSignature) client.getCredentials()).getToken());
        assertEquals("https://myaccount.blob.core.windows.net", client.getEndpoint().toString());
    }

    @Test
    public void testServicePrincipalRefreshesTokenBeforeEachRequest()
    {
        PluginTask task = task(baseConfig().set("auth_method", "service_principal")
                .set("tenant_id", "t").set("client_id", "c").set("client_secret", "s"));
        AtomicInteger calls = new AtomicInteger();
        ServicePrincipalTokenProvider provider = new ServicePrincipalTokenProvider("http://unused", "t", "c", "s", null, () -> 0L) {
            @Override
            public synchronized String getToken()
            {
                return "token-" + calls.incrementAndGet();
            }
        };
        AzureBlobClientFactory factory = new AzureBlobClientFactory(task, provider);

        CloudBlobClient client = factory.createClient();
        StorageCredentialsToken credentials = (StorageCredentialsToken) client.getCredentials();
        assertEquals("token-1", credentials.getToken());

        OperationContext op = factory.createOperationContext();
        assertNotNull(op);
        // The SDK fires this event right before it signs a request.
        op.getSendingRequestEventHandler().fireEvent(new SendingRequestEvent(op, null, null));
        assertEquals("token-2", credentials.getToken());
    }

    @Test
    public void testRequiredOptionsForEachAuthMethod()
    {
        assertThrows(ConfigException.class, () -> AzureBlobClientFactory.validate(task(baseConfig())));
        assertThrows(ConfigException.class, () -> AzureBlobClientFactory.validate(task(baseConfig().set("auth_method", "sas_token"))));
        assertThrows(ConfigException.class, () -> AzureBlobClientFactory.validate(task(baseConfig()
                .set("auth_method", "service_principal").set("tenant_id", "t").set("client_id", "c"))));
        AzureBlobClientFactory.validate(task(baseConfig()
                .set("auth_method", "service_principal").set("tenant_id", "t").set("client_id", "c").set("client_secret", "s")));
    }

    @Test
    public void testUnknownAuthMethod()
    {
        ConfigException ex = assertThrows(ConfigException.class, () -> AuthMethod.of("managed_identity"));
        assertEquals("Unsupported 'auth_method': managed_identity, supported values: account_key, service_principal, sas_token", ex.getMessage());
    }
}
