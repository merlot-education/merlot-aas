package eu.gaiax.difs.aas.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import eu.gaiax.difs.aas.client.InvitationServiceClient;
import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.RestInvitationServiceClientImpl;
import eu.gaiax.difs.aas.client.RestTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.properties.StatusProperties;

@Configuration
public class ClientsConfig {

    @Bean
    @Profile("prod")
    public TrustServiceClient restTrustServiceClient() {
        return new RestTrustServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public TrustServiceClient localTrustServiceClient(StatusProperties statusProperties) {
        return new LocalTrustServiceClientImpl(statusProperties);
    }

    @Bean
    @Profile("prod")
    public InvitationServiceClient restInvitationServiceClient() {
        return new RestInvitationServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public InvitationServiceClient localInvitationServiceClient(StatusProperties statusProperties) {
    	//looks like not implemented yet
        return new RestInvitationServiceClientImpl();
    }
    
}
