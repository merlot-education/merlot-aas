package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.KeycloakClient;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.mapper.AccessRequestMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class IatService {

    private final TrustServiceClient trustServiceClient;
    private final AccessRequestMapper mapper;
    private final KeycloakClient keycloakClient;

    public AccessResponseDto evaluateGetIatProofInvitation(AccessRequestDto accessRequestDto) {
        return mapper.mapToIatAccessResponse(
                evaluate("GetIatProofInvitation", mapper.iatRequestToMap(accessRequestDto))
        );
    }

    public AccessResponseDto evaluateGetIatProofResult(String requestId){
        AccessResponseDto accessResponseDto = mapper.mapToIatAccessResponse(
                evaluate("GetIatProofResult", mapper.iatRequestToMap(requestId))
        );

        if (accessResponseDto.getStatus() == AccessRequestStatusDto.ACCEPTED) {
            accessResponseDto.initialAccessToken(keycloakClient.registerIam(null, null, null, null));
        }
        return accessResponseDto;
    }

    private Map<String, Object> evaluate(String policy, Map<String, Object> params) {
        Map<String, Object> evaluation = trustServiceClient.evaluate(policy, params);

        return evaluation;
    }

}
