package eu.gaiax.difs.aas.client;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.reactive.function.client.WebClient;

import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;

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
        String uri = "/policy/{group}/{policyName}/{version}/{action}";
        // baseUrl doesn't work for some reason, so I specify it here
        ResponseEntity<Map<String, Object>> trustServiceResponse = client.post().uri(url, uriBuilder -> 
                uriBuilder.path(uri).build(group, policy, version, action)) 
            .accept(MediaType.APPLICATION_JSON)
            .bodyValue(params)
            .retrieve()
            .toEntity(MAP_TYPE_REF)
            .block();
        Map<String, Object> result = trustServiceResponse.getBody();
        claims_log.debug("evaluate; got claims: {}", result);

        AccessRequestStatusDto status;
        int code = trustServiceResponse.getStatusCodeValue();
        log.debug("evaluate; got response code: {}", code);
        if (code == HttpStatus.GATEWAY_TIMEOUT.value()) { //504
            status = AccessRequestStatusDto.TIMED_OUT;
        } else if (code >= 400) {
            status = AccessRequestStatusDto.REJECTED;
        } else if (code == HttpStatus.NO_CONTENT.value()) { //204
            status = AccessRequestStatusDto.PENDING;
        } else { // should be 200
            status = AccessRequestStatusDto.ACCEPTED;
        }

        result.remove("claims");
        if (result.size() == 0 && status == AccessRequestStatusDto.ACCEPTED) {
            status = AccessRequestStatusDto.PENDING;
        }
        
        result.put(PN_STATUS, status);
        result.remove(IdTokenClaimNames.SUB);
        result.remove(IdTokenClaimNames.ISS);
        result.remove(IdTokenClaimNames.AUTH_TIME);
        String requestId = (String) result.get(PN_REQUEST_ID);
        if (requestId == null) {
            requestId = (String) params.get(PN_REQUEST_ID);
            // a quick fix for TSA mock..
            result.put(IdTokenClaimNames.SUB, requestId);
        }
        log.debug("evaluate.exit; returning claims: {} with status: {}", result.size(), status);
        return result;
    }
    
}
