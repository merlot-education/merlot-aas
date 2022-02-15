package eu.gaiax.difs.aas.config;

import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.RestTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
public class TrustServiceConfig {
    @Bean
    @Profile("prod")
    public TrustServiceClient prodTrustService() {
        return new RestTrustServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public TrustServiceClient testTrustService() {
        return new LocalTrustServiceClientImpl();
    }
}
