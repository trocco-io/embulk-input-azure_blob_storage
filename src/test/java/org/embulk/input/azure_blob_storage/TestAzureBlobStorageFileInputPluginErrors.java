package org.embulk.input.azure_blob_storage;

import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.StorageExtendedErrorInformation;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.spi.DataException;
import org.junit.Rule;
import org.junit.Test;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

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
        // A token refresh that fails inside the SDK is wrapped in a StorageException.
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException(null, "refresh failed", 306, null, configException)));
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
        assertTrue(ex.getMessage().contains("Signed expiry time has to be after signed start time"));
        assertTrue(ex.getMessage().contains("Check the credentials"));
        assertSame(cause, ex.getCause());
    }

    @Test
    public void testFinalErrorKeepsConfigException()
    {
        ConfigException configException = new ConfigException("wrong client secret");
        RuntimeException ex = AzureBlobStorageFileInputPlugin.toUserException(new StorageException(null, "refresh failed", 306, null, configException));
        assertSame(configException, ex);
    }
}
