package eu.gaiax.difs.aas.client;

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

    private static final Logger log = LoggerFactory.getLogger(RestTrustServiceClientImpl.class);
    private static final Logger claims_log = LoggerFactory.getLogger("tsclaims");

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
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    @Override
    public Map<String, Object> evaluate(String policy, Map<String, Object> params) {
        log.debug("evaluate.enter; got policy: {}, params: {}", policy, params);
        claims_log.debug("evaluate.enter; got policy: {}, params: {}", policy, params);
        String uri = "/{repo}/policies/{group}/{policyname}/{version}/{action}";
        // baseUrl doesn't work for some reason, so I specify it here
        Flux<Map<String, Object>> trustServiceResponse = client.post().uri(url, uriBuilder -> 
                    uriBuilder.path(uri).build(repo, group, policy, version, action)) 
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(params)
                .retrieve()
                .bodyToFlux(MAP_TYPE_REF);
        Map<String, Object> result = trustServiceResponse.blockFirst();
        claims_log.debug("evaluate.exit; returning claims: {}", result);
        log.debug("evaluate.exit; returning claims: {}", result.size());
        return result;
    }
    
}
