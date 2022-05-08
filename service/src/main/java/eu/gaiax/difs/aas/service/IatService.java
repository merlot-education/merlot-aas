package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.IamClient;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import eu.gaiax.difs.aas.properties.ClientsProperties;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class IatService {

    private static final Logger log = LoggerFactory.getLogger(IatService.class);

    private final TrustServiceClient trustServiceClient;
    private final IamClient iamClient;

    private final ClientsProperties clientsProperties;

    public AccessResponseDto evaluateIatProofInvitation(AccessRequestDto accessRequestDto) {
        log.debug("evaluateIatProofInvitation.enter; got request: {}", accessRequestDto);
        Map<String, Object> evalRequest = iatRequestToMap(accessRequestDto);
        Map<String, Object> evalResponse = trustServiceClient.evaluate("GetIatProofInvitation", evalRequest);
        AccessResponseDto accessResponseDto = mapToIatAccessResponse(evalResponse);
        log.debug("evaluateIatProofInvitation.exit; returning: {}", accessResponseDto);
        return accessResponseDto;
    }

    private Map<String, Object> iatRequestToMap(AccessRequestDto request) {
        Map<String, Object> map = new HashMap<>();
        Set<String> scopes = new HashSet<>();
        scopes.add("openid");
        scopes.add(request.getEntity().getScope());
        map.put("scope", scopes);
        map.put("sub", request.getEntity().getDid());
        map.put("iss", request.getSubject());
        map.put("namespace", "Access");
        return map;
    }

    public AccessResponseDto evaluateIatProofResult(String requestId) {
        log.debug("evaluateIatProofResult.enter; got request: {}", requestId);
        Map<String, Object> evalRequest =  Collections.singletonMap("requestId", requestId);
        Map<String, Object> evalResponse = trustServiceClient.evaluate("GetIatProofResult", evalRequest);
        AccessResponseDto accessResponseDto = mapToIatAccessResponse(evalResponse);

        if (accessResponseDto.getStatus() == AccessRequestStatusDto.ACCEPTED) {
            Map<String, Object> regResponse = iamClient.registerIam(accessResponseDto.getSubject(), List.of(clientsProperties.getOidc().getRedirectUri()));
            String iat = (String) regResponse.get("registration_access_token"); // not sure it is correct token!
            accessResponseDto.setInitialAccessToken(iat);
        }
        log.debug("evaluateIatProofResult.exit; returning: {}", accessResponseDto);
        return accessResponseDto;
    }
    
    private AccessResponseDto mapToIatAccessResponse(Map<String, Object> map) {
        return new AccessResponseDto().subject((String) map.getOrDefault("iss", null))
                .entity(mapAccessScope(map)) 
                .status((AccessRequestStatusDto) map.getOrDefault("status", null))
                .initialAccessToken((String) map.getOrDefault("iat", null))
                .requestId((String) map.getOrDefault("requestId", null))
                .policyEvaluationResult(map.getOrDefault("policyEvaluationResult", null));
    }

    private ServiceAccessScopeDto mapAccessScope(Map<String, Object> map) {
        try {
            return new ServiceAccessScopeDto()
                    .scope((String) map.getOrDefault("scope", null))
                    .did((String) map.getOrDefault("sub", null));
        } catch (Exception ignored) {
            return new ServiceAccessScopeDto();
        }
    }
    
}
