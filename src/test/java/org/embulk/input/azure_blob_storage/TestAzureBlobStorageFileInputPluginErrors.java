package org.embulk.input.azure_blob_storage;

import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.StorageExtendedErrorInformation;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.input.azure_blob_storage.AzureBlobStorageFileInputPlugin.PluginTask;
import org.embulk.spi.DataException;
import org.junit.Rule;
import org.junit.Test;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

// Tests that don't need an Azure account
public class TestAzureBlobStorageFileInputPluginErrors
{
    @Rule
    public EmbulkTestRuntime runtime = new EmbulkTestRuntime();

    @Test
    public void testValidatesOptionsBeforeListingFiles()
    {
        ConfigSource config = runtime.getExec().newConfigSource()
                .set("account_name", "myaccount")
                .set("container", "my-container")
                .set("path_prefix", "data/");
        AtomicBoolean ran = new AtomicBoolean(false);

        ConfigException ex = assertThrows(ConfigException.class, () -> new AzureBlobStorageFileInputPlugin()
                .transaction(config, (taskSource, taskCount) -> {
                    ran.set(true);
                    return Collections.emptyList();
                }));
        assertEquals("'account_key' is required for this 'auth_method'.", ex.getMessage());
        assertFalse(ran.get());
    }

    @Test
    public void testConfigErrorsAreNotRetried()
    {
        ConfigException configException = new ConfigException("wrong client secret");
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(configException));
        // A token refresh that fails inside the SDK comes back as a StorageException with the status of the request the
        // SDK then sent unsigned, and the original exception as the cause.
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException("AuthenticationFailed", "auth", 401, null, configException)));
        // Everything else is retried as before.
        assertTrue(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException("AuthenticationFailed", "auth", 403, null, null)));
        assertTrue(AzureBlobStorageFileInputPlugin.isRetryable(new RuntimeException("network")));
    }

    @Test
    public void testFinalErrorIncludesStatusCodeAndDetail()
    {
        StorageExtendedErrorInformation details = new StorageExtendedErrorInformation();
        details.getAdditionalDetails().put("AuthenticationErrorDetail", new String[] {"Signed expiry time has to be after signed start time"});
        details.setErrorCode("AuthenticationFailed");
        StorageException cause = new StorageException("AuthenticationFailed", "Server failed to authenticate the request.", 403, details, null);

        RuntimeException ex = AzureBlobStorageFileInputPlugin.toUserException(cause);
        assertTrue(ex instanceof DataException);
        assertTrue(ex.getMessage().contains("status: 403"));
        assertTrue(ex.getMessage().contains("code: AuthenticationFailed"));
        assertTrue(ex.getMessage().contains("Signed expiry time has to be after signed start time. Check the credentials"));
        assertSame(cause, ex.getCause());
    }

    @Test
    public void testFinalErrorKeepsConfigException()
    {
        ConfigException configException = new ConfigException("wrong client secret");
        RuntimeException ex = AzureBlobStorageFileInputPlugin.toUserException(new StorageException("AuthenticationFailed", "auth", 401, null, configException));
        assertSame(configException, ex);
    }

    @Test
    public void testFinalErrorShowsTheOriginalErrorOfAFailedRefresh()
    {
        RuntimeException refreshError = new ServicePrincipalTokenProvider.RetryableTokenException(
                "Microsoft Entra ID returned a temporary error (status: 503)", null);
        RuntimeException ex = AzureBlobStorageFileInputPlugin.toUserException(
                new StorageException("AuthenticationFailed", "Server failed to authenticate the request.", 401, null, refreshError));
        assertTrue(ex.getMessage().contains("status: 401"));
        assertTrue(ex.getMessage().contains("Caused by: Microsoft Entra ID returned a temporary error (status: 503)"));
    }

    // The client is created inside the retried call, so getting an access token when a file is opened is retried.
    @Test
    public void testTokenErrorsWhenOpeningAFileAreRetried()
    {
        AtomicInteger calls = new AtomicInteger();
        PluginTask task = taskWithOneFile(1);
        AzureBlobClientFactory factory = new AzureBlobClientFactory(task, stubProvider(calls,
                () -> new ServicePrincipalTokenProvider.RetryableTokenException("temporary", null)));
        AzureBlobStorageFileInputPlugin.SingleFileProvider provider =
                new AzureBlobStorageFileInputPlugin().new SingleFileProvider(task, 0, factory);

        assertThrows(DataException.class, provider::openNextWithHints);
        assertEquals(2, calls.get()); // the first try and one retry (max_connection_retry: 1)
    }

    @Test
    public void testConfigErrorsWhenOpeningAFileAreNotRetried()
    {
        AtomicInteger calls = new AtomicInteger();
        PluginTask task = taskWithOneFile(3);
        AzureBlobClientFactory factory = new AzureBlobClientFactory(task, stubProvider(calls,
                () -> new ConfigException("wrong client secret")));
        AzureBlobStorageFileInputPlugin.SingleFileProvider provider =
                new AzureBlobStorageFileInputPlugin().new SingleFileProvider(task, 0, factory);

        ConfigException ex = assertThrows(ConfigException.class, provider::openNextWithHints);
        assertEquals("wrong client secret", ex.getMessage());
        assertEquals(1, calls.get());
    }

    private PluginTask taskWithOneFile(int maxConnectionRetry)
    {
        ConfigSource config = runtime.getExec().newConfigSource()
                .set("account_name", "myaccount")
                .set("auth_method", "service_principal")
                .set("tenant_id", "t").set("client_id", "c").set("client_secret", "s")
                .set("container", "my-container")
                .set("path_prefix", "data/")
                .set("max_connection_retry", maxConnectionRetry);
        PluginTask task = AzureBlobStorageFileInputPlugin.CONFIG_MAPPER.map(config, PluginTask.class);
        FileList.Builder builder = new FileList.Builder(task);
        builder.add("data/a.csv", 10);
        task.setFiles(builder.build());
        return task;
    }

    private static ServicePrincipalTokenProvider stubProvider(AtomicInteger calls, Supplier<RuntimeException> error)
    {
        return new ServicePrincipalTokenProvider("http://unused", "t", "c", "s", null, () -> 0L, millis -> { }) {
            @Override
            public synchronized String getToken()
            {
                calls.incrementAndGet();
                throw error.get();
            }
        };
    }
}
