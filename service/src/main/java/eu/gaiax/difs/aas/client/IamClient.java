package eu.gaiax.difs.aas.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class IamClient {

    private final WebClient client;
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE_REF = new ParameterizedTypeReference<>() {
    };

    @Value("${aas.iam.base-uri}")
    private String baseUri;

    @Value("${aas.iam.client-registration-uri}")
    private String clientRegistrationUri;

    @Value("${aas.iam.client-iat}")
    private String clientIat;

    public IamClient() {
        client = WebClient.builder()
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
        }

    public Map<String, Object> registerIam(String clientName, List<String> redirectUris) {

        Map<String, Object> map = new HashMap<>();
        map.put("client_name", clientName);
        map.put("redirect_uris", redirectUris);
        map.put("grant_types", List.of("authorization_code"));

        Flux<Map<String, Object>> trustServiceResponse = client.post()
                .uri(baseUri+clientRegistrationUri)
                .headers(h -> h.setBearerAuth(clientIat))
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(map)
                .retrieve()
                .bodyToFlux(MAP_TYPE_REF);

        return trustServiceResponse.blockFirst();
    }
}
