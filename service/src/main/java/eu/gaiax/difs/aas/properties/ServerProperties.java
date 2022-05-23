package eu.gaiax.difs.aas.properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
public class ServerProperties {

    @Value("${server.ssl.enabled}")
    private boolean sslEnabled;
    @Value("${server.host}")
    private String serverHost;
    @Value("${server.port}")
    private String serverPort;
    @Value("${server.schema}")
    private String serverSchema;

    public String getBaseUrl() {
        //return (sslEnabled ? "https" : "http") + "://" + serverHost + ":" + serverPort;
        return serverSchema + "://" + serverHost + ":" + serverPort;
    }
}
