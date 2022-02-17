package eu.gaiax.difs.aas.mapper;

import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class IatDtoMapper {

    public Map<String, Object> requestToMap(AccessRequestDto request) {
        Map<String, Object> map = new HashMap<>();
        map.put("scope", List.of("openid", request.getObject().getScope()));
        map.put("sub", request.getObject().getDid());
        map.put("iss", request.getSubject());
        map.put("namespace", "Access");
        return map;
    }

    public AccessResponseDto mapToResponse(Map<String, Object> map) {
        return new AccessResponseDto()
                .subject((String) map.getOrDefault("iss", null))
                ._object(mapAccessScope(map.getOrDefault("object", null)))
                // TODO: claims to be specified
                .requestId((String) map.getOrDefault("requestId", null))
                .status(mapStatus(map.getOrDefault("status", null)))
                .policyEvaluationResult(map.getOrDefault("policyEvaluationResult", null))
                .initialAccessToken((String) map.getOrDefault("initialAccessToken", null));
    }

    private ServiceAccessScopeDto mapAccessScope(Object input) {
        try {
            Map<String, String> map = (Map<String, String>) input;
            return new ServiceAccessScopeDto()
                    .scope(map.getOrDefault("scope", null))
                    .did(map.getOrDefault("sub", null));
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
