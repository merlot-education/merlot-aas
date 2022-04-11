package eu.gaiax.difs.aas.client;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

public class RestTrustServiceClientImpl implements TrustServiceClient {

    private static final Logger log = LoggerFactory.getLogger("tsclaims");

    private final WebClient client;
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE_REF = new ParameterizedTypeReference<>() {
    };

    @Value("${aas.tsa.url}")
    private String url;
    @Value("${aas.tsa.repo}")
    private String repo;
    @Value("${aas.tsa.group}")
    private String group;
    @Value("${aas.tsa.version}")
    private String version;
    @Value("${aas.tsa.action}")
    private String action;

    public RestTrustServiceClientImpl() {
        client = WebClient.builder().baseUrl(url)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).build();
    }

    @Override
    public Map<String, Object> evaluate(String policyName, Map<String, Object> bodyParams) {
        String uri = "/{repo}/policies/{group}/{policyname}/{version}/{action}";
        Map<String, String> uriParams = new HashMap<>();
        uriParams.put("repo", repo);
        uriParams.put("group", group);
        uriParams.put("policyname", policyName);
        uriParams.put("version", version);
        uriParams.put("action", action);

        Flux<Map<String, Object>> trustServiceResponse = client.post().uri(uri, uriParams)
                .accept(MediaType.APPLICATION_JSON).bodyValue(bodyParams).retrieve().bodyToFlux(MAP_TYPE_REF);

        Map<String, Object> result = trustServiceResponse.blockFirst();

        log.debug("\nCalled trust service client: \n" +
                "policy: {} \n" +
                "params: {} \n" +
                "result: {} ", policyName, bodyParams, result);

        return result;
    }
}
