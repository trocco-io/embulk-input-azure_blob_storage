package org.embulk.input.azure_blob_storage;

import com.microsoft.azure.storage.OperationContext;
import com.microsoft.azure.storage.RetryNoRetry;
import com.microsoft.azure.storage.StorageCredentialsAccountAndKey;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.StorageExtendedErrorInformation;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.sun.net.httpserver.HttpServer;
import org.embulk.EmbulkTestRuntime;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.input.azure_blob_storage.AzureBlobStorageFileInputPlugin.PluginTask;
import org.embulk.spi.DataException;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
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
        assertEquals("'account_key' is required when 'auth_method' is 'account_key'.", ex.getMessage());
        assertFalse(ran.get());
    }

    @Test
    public void testConfigErrorsAreNotRetried()
    {
        ConfigException configException = new ConfigException("wrong client secret");
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(configException));
        // A token refresh that fails inside the SDK comes back as a StorageException with status 306 and the original
        // exception as the cause (the request is not sent).
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException(null, "wrong client secret", 306, null, configException)));
        // An error of Entra ID that is not temporary is not retried; a temporary one is.
        assertFalse(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException(null, "unexpected", 306, null,
                new ServicePrincipalTokenProvider.TokenRequestException("unexpected status", null))));
        assertTrue(AzureBlobStorageFileInputPlugin.isRetryable(new StorageException(null, "temporary", 306, null,
                new ServicePrincipalTokenProvider.RetryableTokenException("temporary", null))));
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

    // The SDK catches an exception thrown before signing (e.g. a failed refresh) and throws this, without sending the
    // request
    @Test
    public void testFinalErrorOfAFailedRefreshShowsOnlyTheOriginalError()
    {
        RuntimeException refreshError = new ServicePrincipalTokenProvider.RetryableTokenException(
                "Microsoft Entra ID returned a temporary error (status: 503)", null);
        RuntimeException ex = AzureBlobStorageFileInputPlugin.toUserException(
                new StorageException(null, refreshError.getMessage(), 306, null, refreshError));
        assertTrue(ex instanceof DataException);
        assertEquals("Microsoft Entra ID returned a temporary error (status: 503)", ex.getMessage());
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

    // A retry lists again from the first page, so the files of the pages listed before the failure must not be added twice
    @Test
    public void testRetryOfListingDoesNotAddFilesTwice() throws IOException
    {
        AtomicInteger secondPageRequests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getRawQuery();
            int status = 200;
            String body = "";
            if ("HEAD".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().add("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT");
                exchange.getResponseHeaders().add("ETag", "\"0x1\"");
                exchange.getResponseHeaders().add("x-ms-blob-type", "BlockBlob");
                exchange.sendResponseHeaders(200, -1);
                exchange.close();
                return;
            }
            if (query != null && query.contains("marker=page2")) {
                if (secondPageRequests.incrementAndGet() == 1) {
                    // The second page fails once with a temporary error, after the first page was listed
                    status = 503;
                    body = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>ServerBusy</Code><Message>busy</Message></Error>";
                }
                else {
                    body = listResponse("data/b.csv", null);
                }
            }
            else if (path.endsWith("/my-container")) {
                body = listResponse("data/a.csv", "page2");
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/xml");
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        try {
            PluginTask task = AzureBlobStorageFileInputPlugin.CONFIG_MAPPER.map(runtime.getExec().newConfigSource()
                    .set("account_name", "myaccount").set("account_key", "a2V5")
                    .set("container", "my-container").set("path_prefix", "data/"), PluginTask.class);
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/myaccount");
            AzureBlobClientFactory factory = new AzureBlobClientFactory(task, null) {
                @Override
                public CloudBlobClient createClient()
                {
                    CloudBlobClient client = new CloudBlobClient(endpoint, new StorageCredentialsAccountAndKey("myaccount", "a2V5"));
                    // Fail at once, so the retry of the plugin is the one tested
                    client.getDefaultRequestOptions().setRetryPolicyFactory(new RetryNoRetry());
                    return client;
                }

                @Override
                public OperationContext createOperationContext()
                {
                    return null;
                }
            };

            FileList fileList = AzureBlobStorageFileInputPlugin.listFilesWithPrefix(task, factory, "my-container", "data/",
                    Optional.empty(), 1, 1);

            List<String> paths = new ArrayList<>();
            for (int i = 0; i < fileList.getTaskCount(); i++) {
                paths.addAll(fileList.get(i));
            }
            assertEquals(2, secondPageRequests.get());
            assertEquals(Arrays.asList("data/a.csv", "data/b.csv"), paths);
        }
        finally {
            server.stop(0);
        }
    }

    private static String listResponse(String name, String nextMarker)
    {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults ContainerName=\"my-container\"><Blobs><Blob>"
                + "<Name>" + name + "</Name><Properties><Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>"
                + "<Etag>0x1</Etag><Content-Length>10</Content-Length><BlobType>BlockBlob</BlobType></Properties>"
                + "</Blob></Blobs><NextMarker>" + (nextMarker == null ? "" : nextMarker) + "</NextMarker></EnumerationResults>";
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
