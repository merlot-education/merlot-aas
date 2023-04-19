package eu.gaiax.difs.aas.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.gaiax.difs.aas.service.SsiAuthorizationService;
import eu.gaiax.difs.aas.service.SsiClientsRepository;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class ClientRegistrationTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private SsiClientsRepository clientsRepo;
    @Autowired
    private SsiAuthorizationService authService;

    @Test
    void readClientTest() throws Exception {
    	String clientId = "aas-app-oidc";
    	String clientSecret = "{noop}secret";
    	Jwt jwt = buildJwt(clientId, "client.read");
        MvcResult result = mockMvc.perform(get("/connect/register?client_id={clientId}", clientId)
        		.with(jwt().jwt(jwt)))
                .andExpect(status().isOk()).andReturn();
        Map<String, Object> client = mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertEquals(clientId, client.get("client_id").toString());
        assertEquals(clientSecret, client.get("client_secret").toString());
        assertEquals(List.of("refresh_token", "client_credentials", "authorization_code"), client.get("grant_types"));
        assertEquals(List.of("http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint"), client.get("redirect_uris"));
        assertEquals("openid profile email", client.get("scope").toString());
    }
    
    @Test
    void registerClientTest() throws Exception {
    	List<RegisteredClient> clients = clientsRepo.getAllClients();
    	assertEquals(4, clients.size());
    	String json = "{\"application_type\": \"web\", \"client_name\": \"My Web App\", \"grant_types\": [\"authorization_code\", \"client_credentials\"], " + 
    			"\"redirect_uris\": [\"http://new.client.com/test\", \"https://new.client.org/endpoint\"], \"response_types\": [\"code\"], " + 
    			"\"scope\": \"openid profile email\", \"my_custom_parameters\": {\"limit\": 32, \"restriction\": \"constraint\", \"enabled\": true}}";
    	Jwt jwt = buildJwt("aas-app-oidc", "client.create");
        MvcResult result = mockMvc.perform(post("/connect/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json)
        		.with(jwt().jwt(jwt)))
                .andExpect(status().isCreated()).andReturn();
        Map<String, Object> client = mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertEquals("My Web App", client.get("client_name").toString());
        assertEquals(List.of("client_credentials", "authorization_code"), client.get("grant_types"));
        assertEquals(List.of("https://new.client.org/endpoint", "http://new.client.com/test"), client.get("redirect_uris"));
        assertEquals(List.of("code"), client.get("response_types"));
        clients = clientsRepo.getAllClients();
        assertEquals(5, clients.size());
        String clientId = client.get("client_id").toString();
    	RegisteredClient reClient = clientsRepo.findByClientId(clientId);
    	assertNotNull(reClient);
    	assertEquals(clientId, reClient.getClientId());
    	assertEquals(client.get("client_secret").toString(), reClient.getClientSecret());
        assertEquals("My Web App", reClient.getClientName());
        assertEquals(Set.of("profile", "openid", "email"), reClient.getScopes());
        ClientSettings cs = reClient.getClientSettings();
        assertNotNull(cs);
    }
  
    private Jwt buildJwt(String clientId, String clientScope) {
    	RegisteredClient reClient = clientsRepo.findByClientId(clientId);
    	OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(reClient)
    			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    			.principalName("test-user")
    			.token(new OAuth2AuthorizationCode("client-token", Instant.now(), Instant.now().plusSeconds(10)))
    			.token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "client-token", Instant.now(), Instant.now().plusSeconds(10)), 
    					m -> m.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of("scope", List.of(clientScope))))
    			.build();
    	authService.save(auth);
    	return Jwt.withTokenValue("client-token") 
    			.header("alg", "none")
    			.claim("sub", "test-user")
    			.build();
    }
}
