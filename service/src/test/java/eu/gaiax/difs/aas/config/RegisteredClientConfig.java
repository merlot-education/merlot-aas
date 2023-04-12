package eu.gaiax.difs.aas.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import eu.gaiax.difs.aas.properties.ClientsProperties;
import lombok.extern.slf4j.Slf4j;
import eu.gaiax.difs.aas.properties.ClientsProperties.ClientProperties;
import eu.gaiax.difs.aas.service.SsiClientsRepository;

@Slf4j
@Configuration
public class RegisteredClientConfig {

    @Value("${aas.token.ttl}")
    private Duration tokenTtl;
	
    private final ClientsProperties clientsProperties;

    @Autowired
    public RegisteredClientConfig(ClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
    }
    
    @Bean
    @Profile("dev")    
    public SsiClientsRepository registeredClientRepository(JdbcTemplate jdbcTemplate) throws Exception {
        Map<String, ClientProperties> clients = clientsProperties.getClients();
        if (clients == null) {
            log.error("registeredClientRepository.error. No Clients Registered! Check your configuration for errors if this is not intentional.");
            throw new Exception("No Clients registered");
        }        
    	log.info("registeredClientRepository.enter; declared clients: {}", clients.size());

    	int[] cnt = new int[] {0};
    	SsiClientsRepository clientsRepo = new SsiClientsRepository(jdbcTemplate);
    	clients.values().stream()
    		.forEach(cp -> {
    			RegisteredClient client = prepareClient(cp);
    			if (client != null) {
    				clientsRepo.save(client);
    				cnt[0]++;
    			}
    		});	
    	log.info("registeredClientRepository.exit; registered clients: {}", cnt[0]);
    	return clientsRepo;
    }	
	
    private RegisteredClient prepareClient(ClientProperties client) {
    	log.debug("prepareClient.enter; client: {}", client);
    	RegisteredClient.Builder rcBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.getId())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUris(c -> c.addAll(client.getRedirectUris()))
                .scopes(c -> c.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)))
                .clientSettings(ClientSettings.builder()
                	// can be used for PKCE, but not strictly required
                	//.requireAuthorizationConsent(false) 
                	//.requireProofKey(true)
                      .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                    // maybe we'll use it later on..
                    //.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
                    .build())
                .tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(tokenTtl)
                    .build());    	
        if (client.getSecret() == null || client.getSecret().isEmpty()) {
            rcBuilder = rcBuilder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            rcBuilder = rcBuilder
                .clientSecret(client.getSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }
        return rcBuilder.build();
    }
	
}
