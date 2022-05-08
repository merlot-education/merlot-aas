package eu.gaiax.difs.aas.config;

import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.RestTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.properties.ServerProperties;
import eu.gaiax.difs.aas.properties.StatusProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
public class TrustServiceClientConfig {

    @Bean
    @Profile("prod")
    public TrustServiceClient restTrustServiceClient() {
        return new RestTrustServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public TrustServiceClient localTrustServiceClient(ServerProperties serverProperties, StatusProperties statusProperties) {
        return new LocalTrustServiceClientImpl(serverProperties, statusProperties);
    }

}
