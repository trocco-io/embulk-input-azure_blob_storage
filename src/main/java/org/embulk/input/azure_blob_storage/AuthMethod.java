package org.embulk.input.azure_blob_storage;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.embulk.config.ConfigException;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * How the plugin authenticates to Azure Blob Storage.
 */
public enum AuthMethod
{
    ACCOUNT_KEY("account_key"),
    SERVICE_PRINCIPAL("service_principal"),
    SAS_TOKEN("sas_token");

    private final String value;

    AuthMethod(String value)
    {
        this.value = value;
    }

    public String getValue()
    {
        return value;
    }

    @JsonCreator
    public static AuthMethod of(String value)
    {
        for (AuthMethod method : values()) {
            if (method.value.equals(value)) {
                return method;
            }
        }
        throw new ConfigException("Unsupported 'auth_method': " + value + ", supported values: "
                + Arrays.stream(values()).map(AuthMethod::getValue).collect(Collectors.joining(", ")));
    }
}
