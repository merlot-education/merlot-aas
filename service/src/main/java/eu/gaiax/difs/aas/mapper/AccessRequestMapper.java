package eu.gaiax.difs.aas.mapper;

import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class AccessRequestMapper {

    public Map<String, Object> loginRequestToMap(AccessRequestDto request) {
        Map<String, Object> map = new HashMap<>();
        if (request.getEntity().getScope() != null) map.put("scope", List.of("openid", request.getEntity().getScope()));
        map.put("namespace", "Login");
        map.put("not_older_than", ""); //TODO
        map.put("max_age", ""); //TODO
        return map;
    }

    public AccessResponseDto mapTologinAccessResponse(Map<String, Object> map) {
        return new AccessResponseDto()
                .requestId((String) map.getOrDefault("requestId", null))
                // TODO: claims to be specified
                .policyEvaluationResult(map.getOrDefault("link", null));
    }

    public Map<String, Object> iatRequestToMap(AccessRequestDto request) {
        Map<String, Object> map = new HashMap<>();
        if (request.getEntity().getScope() != null) map.put("scope", List.of("openid", request.getEntity().getScope()));
        map.put("sub", request.getEntity().getDid());
        map.put("iss", request.getSubject());
        map.put("namespace", "Access");
        return map;
    }

    public Map<String, Object> iatRequestToMap(String requestId) {
        return Collections.singletonMap("requestId", requestId);
    }

    public AccessResponseDto mapToIatAccessResponse(Map<String, Object> map) {
        return new AccessResponseDto().subject((String) map.getOrDefault("iss", null))
                .entity(mapAccessScope(map.getOrDefault("sub", null)))
                .status(mapStatus(map.getOrDefault("status", null)))
                .initialAccessToken((String) map.getOrDefault("iat", null))
                // TODO: claims to be specified
                .requestId((String) map.getOrDefault("requestId", null))
                .policyEvaluationResult(map.getOrDefault("policyEvaluationResult", null));
    }

    private ServiceAccessScopeDto mapAccessScope(Object input) {
        try {
            Map<String, String> map = (Map<String, String>) input;
            return new ServiceAccessScopeDto().scope(map.getOrDefault("scope", null))
                    .did(map.getOrDefault("did", null));
        } catch (Exception ignored) {
            return new ServiceAccessScopeDto();
        }
    }

    private AccessRequestStatusDto mapStatus(Object input) {
        if (input instanceof String) {
            return AccessRequestStatusDto.fromValue((String) input);
        }
        return null;
    }

}
