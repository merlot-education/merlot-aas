package eu.gaiax.difs.aas.client;

import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistration;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class KeycloakClient {

    @Value("${aas.keycloak.url}")
    private String url;

    @Value("${aas.keycloak.initial-token}")
    private String token;

    public String registerIam(String clientId, String name, List<String> redirectUris, String baseUrl) {
        ClientRegistration clientReg = ClientRegistration.create().url(url + "/auth", "gaia-x").build();
        clientReg.auth(Auth.token(token));
        ClientRepresentation client = new ClientRepresentation();
        client.setEnabled(true);
        client.setClientId(clientId);
        client.setName(name);
        client.setRedirectUris(redirectUris); //List.of("http://localhost:8080/redirect")
        client.setBaseUrl(baseUrl);
        ClientRepresentation response = null;
        try {
            response = clientReg.create(client);
        } catch (ClientRegistrationException e) {
            e.printStackTrace();
        }
//        String registrationAccessToken = response.getRegistrationAccessToken();
//        try {
//            JsonWebToken registrationToken = new JWSInput(registrationAccessToken).readJsonContent(JsonWebToken.class);
//        } catch (JWSInputException e) {
//            e.printStackTrace();
//        }

        return response.getRegistrationAccessToken();
    }
}
