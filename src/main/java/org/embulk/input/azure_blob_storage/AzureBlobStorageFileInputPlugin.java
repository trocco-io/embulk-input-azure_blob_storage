package org.embulk.input.azure_blob_storage;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import org.embulk.config.ConfigDiff;
import org.embulk.config.ConfigException;
import org.embulk.config.ConfigSource;
import org.embulk.config.TaskReport;
import org.embulk.config.TaskSource;
import org.embulk.spi.DataException;
import org.embulk.spi.Exec;
import org.embulk.spi.FileInputPlugin;
import org.embulk.spi.TransactionalFileInput;
import org.embulk.util.config.Config;
import org.embulk.util.config.ConfigDefault;
import org.embulk.util.config.ConfigMapper;
import org.embulk.util.config.ConfigMapperFactory;
import org.embulk.util.config.Task;
import org.embulk.util.file.InputStreamFileInput;
import org.embulk.util.file.InputStreamFileInput.InputStreamWithHints;
import org.embulk.util.retryhelper.RetryExecutor;
import org.embulk.util.retryhelper.RetryGiveupException;
import org.embulk.util.retryhelper.Retryable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.microsoft.azure.storage.OperationContext;
import com.microsoft.azure.storage.ResultContinuation;
import com.microsoft.azure.storage.ResultContinuationType;
import com.microsoft.azure.storage.ResultSegment;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.StorageExtendedErrorInformation;
import com.microsoft.azure.storage.blob.CloudBlob;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.ListBlobItem;

public class AzureBlobStorageFileInputPlugin
        implements FileInputPlugin
{
    public interface PluginTask
            extends Task, FileList.Task
    {
        @Config("account_name")
        String getAccountName();

        @Config("auth_method")
        @ConfigDefault("\"account_key\"")
        AuthMethod getAuthMethod();

        // auth_method: account_key
        @Config("account_key")
        @ConfigDefault("null")
        Optional<String> getAccountKey();

        // auth_method: service_principal
        @Config("tenant_id")
        @ConfigDefault("null")
        Optional<String> getTenantId();

        @Config("client_id")
        @ConfigDefault("null")
        Optional<String> getClientId();

        @Config("client_secret")
        @ConfigDefault("null")
        Optional<String> getClientSecret();

        // auth_method: sas_token
        @Config("sas_token")
        @ConfigDefault("null")
        Optional<String> getSasToken();

        @Config("container")
        String getContainer();

        @Config("path_prefix")
        String getPathPrefix();

        @Config("incremental")
        @ConfigDefault("true")
        boolean getIncremental();

        @Config("last_path")
        @ConfigDefault("null")
        Optional<String> getLastPath();

        @Config("max_results")
        @ConfigDefault("5000")
        int getMaxResults();

        @Config("max_connection_retry")
        @ConfigDefault("10") // 10 times retry to connect Azure Blob Storage if failed.
        int getMaxConnectionRetry();

        @Config("proxy")
        @ConfigDefault("null")
        Optional<ProxyTask> getProxy();

        @Config("stop_when_file_not_found")
        @ConfigDefault("false")
        boolean getStopWhenFileNotFound();

        FileList getFiles();
        void setFiles(FileList files);
    }

    private static final Logger log = LoggerFactory.getLogger(AzureBlobStorageFileInputPlugin.class);

    public static final ConfigMapperFactory CONFIG_MAPPER_FACTORY = ConfigMapperFactory
        .builder()
        .addDefaultModules()
        .build();
    public static final ConfigMapper CONFIG_MAPPER = CONFIG_MAPPER_FACTORY.createConfigMapper();

    @Override
    public ConfigDiff transaction(ConfigSource config, FileInputPlugin.Control control)
    {
        final PluginTask task = CONFIG_MAPPER.map(config, PluginTask.class);
        AzureBlobClientFactory.validate(task);
        if (task.getProxy().isPresent()) {
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        }
        task.setFiles(listFiles(task));

        return resume(task.toTaskSource(), task.getFiles().getTaskCount(), control);
    }

    @Override
    public ConfigDiff resume(TaskSource taskSource, int taskCount, FileInputPlugin.Control control)
    {
        PluginTask task = CONFIG_MAPPER_FACTORY.createTaskMapper().map(taskSource, PluginTask.class);
        control.run(taskSource, taskCount);

        ConfigDiff configDiff = CONFIG_MAPPER_FACTORY.newConfigDiff();
        if (task.getIncremental()) {
            configDiff.set("last_path", task.getFiles().getLastPath(task.getLastPath()));
        }

        return configDiff;
    }

    @Override
    public void cleanup(TaskSource taskSource, int taskCount, List<TaskReport> successTaskReports)
    {
    }

    private FileList listFiles(PluginTask task)
    {
        if (task.getPathPrefix().equals("/")) {
            log.info("Listing files with prefix \"/\". This doesn't mean all files in a bucket. If you intend to read all files, use \"path_prefix: ''\" (empty string) instead.");
        }
        FileList.Builder builder = new FileList.Builder(task);

        FileList fileList = listFilesWithPrefix(builder, new AzureBlobClientFactory(task), task.getContainer(), task.getPathPrefix(),
                                    task.getLastPath(), task.getMaxResults(), task.getMaxConnectionRetry());

        if (fileList.getTaskCount() == 0 && task.getStopWhenFileNotFound()) {
            throw new ConfigException("No file is found. \"stop_when_file_not_found\" option is \"true\".");
        }

        return fileList;

    }

    private static FileList listFilesWithPrefix(final FileList.Builder builder, final AzureBlobClientFactory clientFactory,
                                                final String containerName, final String prefix, final Optional<String> lastPath,
                                                final int maxResults, final int maxConnectionRetry)
    {
        final String lastKey = (lastPath.isPresent() && !lastPath.get().isEmpty()) ? createNextToken(lastPath.get()) : null;
        try {
            return RetryExecutor.builder()
                    .withRetryLimit(maxConnectionRetry)
                    .withInitialRetryWaitMillis(500)
                    .withMaxRetryWaitMillis(30 * 1000)
                    .build().runInterruptible(new Retryable<FileList>() {
                        @Override
                        public FileList call() throws StorageException, URISyntaxException, IOException
                        {
                            CloudBlobClient client = clientFactory.createClient();
                            ResultContinuation token = null;
                            if (lastKey != null) {
                                token = new ResultContinuation();
                                token.setContinuationType(ResultContinuationType.BLOB);
                                log.debug("lastPath: {}", lastPath.get());
                                log.debug("lastPath(Base64encoded): {}", lastKey);
                                token.setNextMarker(lastKey);
                            }

                            CloudBlobContainer container = client.getContainerReference(containerName);
                            ResultSegment<ListBlobItem> blobs;
                            do {
                                // A new context for each page, as the SDK keeps the result of every request in it
                                final OperationContext op = clientFactory.createOperationContext();
                                blobs = container.listBlobsSegmented(prefix, true, null, maxResults, token, null, op);
                                // For the existence check of each blob, without the SDK's request logging that a proxy turns on
                                final OperationContext existsOp = clientFactory.createOperationContext();
                                if (existsOp != null) {
                                    existsOp.setLoggingEnabled(false);
                                }
                                log.debug(String.format("result count(include directory):%s continuationToken:%s", blobs.getLength(), blobs.getContinuationToken()));
                                for (ListBlobItem blobItem : blobs.getResults()) {
                                    if (blobItem instanceof CloudBlob) {
                                        CloudBlob blob = (CloudBlob) blobItem;
                                        // Pass the context so this request also uses a refreshed token (service_principal)
                                        if (blob.exists(null, null, existsOp) && !blob.getUri().toString().endsWith("/")) {
                                            if (lastPath.isPresent()
                                                    && !lastPath.get().isEmpty()
                                                    && blob.getName().equals(lastPath.get())) {
                                                log.info("skip {} because match with last_path {}", blob.getName(), lastPath.get());
                                                continue;
                                            }
                                            builder.add(blob.getName(), blob.getProperties().getLength());
                                            log.debug(String.format("name:%s, class:%s, uri:%s", blob.getName(), blob.getClass(), blob.getUri()));
                                        }
                                    }
                                }
                                token = blobs.getContinuationToken();
                            } while (blobs.getContinuationToken() != null);
                            return builder.build();
                        }

                        @Override
                        public boolean isRetryableException(Exception exception)
                        {
                            return isRetryable(exception);
                        }

                        @Override
                        public void onRetry(Exception exception, int retryCount, int retryLimit, int retryWait)
                                throws RetryGiveupException
                        {
                            String message = String.format("Azure GET request failed. Retrying %d/%d after %d seconds. Message: %s",
                                    retryCount, retryLimit, retryWait / 1000, exception.getMessage());
                            if (retryCount % 3 == 0) {
                                log.warn(message, exception);
                            }
                            else {
                                log.warn(message);
                            }
                        }

                        @Override
                        public void onGiveup(Exception firstException, Exception lastException)
                                throws RetryGiveupException
                        {
                        }
                    });
        }
        catch (RetryGiveupException ex) {
            throw toUserException(ex.getCause());
        }
        catch (InterruptedException ex) {
            throw new DataException(ex);
        }
    }

    @Override
    public TransactionalFileInput open(TaskSource taskSource, int taskIndex)
    {
        PluginTask task = CONFIG_MAPPER_FACTORY.createTaskMapper().map(taskSource, PluginTask.class);
        return new AzureFileInput(task, taskIndex);
    }

    class AzureFileInput
            extends InputStreamFileInput
            implements TransactionalFileInput
    {
        public AzureFileInput(PluginTask task, int taskIndex)
        {
            super(Exec.getBufferAllocator(), new SingleFileProvider(task, taskIndex));
        }
        public void abort() {}

        public TaskReport commit()
        {
            return CONFIG_MAPPER_FACTORY.newTaskReport();
        }

        @Override
        public void close() {}
    }

    class SingleFileProvider
            implements InputStreamFileInput.Provider
    {
        private final AzureBlobClientFactory clientFactory;
        private final String containerName;
        private final Iterator<String> iterator;
        private final int maxConnectionRetry;
        private boolean opened = false;

        public SingleFileProvider(PluginTask task, int taskIndex)
        {
            this.clientFactory = new AzureBlobClientFactory(task);
            this.containerName = task.getContainer();
            this.iterator = task.getFiles().get(taskIndex).iterator();
            this.maxConnectionRetry = task.getMaxConnectionRetry();
        }

        @Override
        public InputStreamWithHints openNextWithHints()
        {
            if (opened || !iterator.hasNext()) {
                return null;
            }
            final String key = iterator.next();
            opened = true;
            try {
                return  RetryExecutor.builder()
                    .withRetryLimit(maxConnectionRetry)
                    .withInitialRetryWaitMillis(500)
                    .withMaxRetryWaitMillis(30 * 1000)
                    .build().runInterruptible(new Retryable<InputStreamWithHints>() {
                            @Override
                            public InputStreamFileInput.InputStreamWithHints call() throws StorageException, URISyntaxException, IOException
                            {
                                // Created here so that getting an access token (service_principal) is retried like the request
                                CloudBlobClient client = clientFactory.createClient();
                                OperationContext op = clientFactory.createOperationContext();
                                CloudBlobContainer container = client.getContainerReference(containerName);
                                CloudBlob blob = container.getBlockBlobReference(key);
                                return new InputStreamFileInput.InputStreamWithHints(
                                        blob.openInputStream(0, null, null, null, op),
                                        String.format("%s/%s", containerName, key)
                                );
                            }

                            @Override
                            public boolean isRetryableException(Exception exception)
                            {
                                return isRetryable(exception);
                            }

                            @Override
                            public void onRetry(Exception exception, int retryCount, int retryLimit, int retryWait)
                                    throws RetryGiveupException
                            {
                                String message = String.format("Azure Blob Storage GET request failed. Retrying %d/%d after %d seconds. Message: %s",
                                        retryCount, retryLimit, retryWait / 1000, exception.getMessage());
                                if (retryCount % 3 == 0) {
                                    log.warn(message, exception);
                                }
                                else {
                                    log.warn(message);
                                }
                            }

                            @Override
                            public void onGiveup(Exception firstException, Exception lastException)
                                    throws RetryGiveupException
                            {
                            }
                        });
            }
            catch (RetryGiveupException ex) {
                throw toUserException(ex.getCause());
            }
            catch (InterruptedException ex) {
                throw new DataException(ex);
            }
        }

        @Override
        public void close() {}
    }

    // Configuration errors (e.g. a wrong client secret) don't go away on retry. Everything else is retried as before.
    static boolean isRetryable(Throwable exception)
    {
        return findConfigException(exception) == null;
    }

    // Makes the final error say why the request failed, instead of only the SDK's generic message.
    static RuntimeException toUserException(Throwable cause)
    {
        ConfigException configException = findConfigException(cause);
        if (configException != null) {
            return configException;
        }
        if (cause instanceof StorageException) {
            StorageException storageException = (StorageException) cause;
            StringBuilder message = new StringBuilder(String.format("Azure Blob Storage request failed (status: %d, code: %s): %s",
                    storageException.getHttpStatusCode(), storageException.getErrorCode(), storageException.getMessage()));
            StorageExtendedErrorInformation details = storageException.getExtendedErrorInformation();
            if (details != null && details.getAdditionalDetails() != null) {
                details.getAdditionalDetails().forEach((key, values) ->
                        message.append(" ").append(key).append(": ").append(String.join(", ", values)));
            }
            int status = storageException.getHttpStatusCode();
            if (status == 401 || status == 403) {
                message.append(" Check the credentials for 'auth_method' (wrong or expired key or SAS token, or missing role or permission).");
            }
            return new DataException(message.toString(), storageException);
        }
        return new DataException(cause);
    }

    private static ConfigException findConfigException(Throwable exception)
    {
        for (Throwable t = exception; t != null; t = t.getCause()) {
            if (t instanceof ConfigException) {
                return (ConfigException) t;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return null;
    }

    private static String createNextToken(String path)
    {
        StringBuilder sb = new StringBuilder()
                .append(String.format("%06d", path.length()))
                .append("!")
                .append(path)
                .append("!000028!9999-12-31T23:59:59.9999999Z!");

        String encodedString = BaseEncoding.base64().encode(sb.toString().getBytes(Charsets.UTF_8));

        StringBuilder marker = new StringBuilder()
                .append("2")
                .append("!")
                .append(encodedString.length())
                .append("!")
                .append(encodedString);
        return marker.toString();
    }
}
