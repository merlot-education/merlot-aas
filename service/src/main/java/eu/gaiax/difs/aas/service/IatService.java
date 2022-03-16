package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.IamClient;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.mapper.AccessRequestMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class IatService {

    private final TrustServiceClient trustServiceClient;
    private final AccessRequestMapper mapper;
    private final IamClient iamClient;

    @Value("${aas.iam.redirect-uri}")
    private String redirectUri;


    public AccessResponseDto evaluateGetIatProofInvitation(AccessRequestDto accessRequestDto) {
        return mapper.mapToIatAccessResponse(
                trustServiceClient.evaluate("GetIatProofInvitation", mapper.iatRequestToMap(accessRequestDto))
        );
    }

    public AccessResponseDto evaluateGetIatProofResult(String requestId){
        AccessResponseDto accessResponseDto = mapper.mapToIatAccessResponse(
                trustServiceClient.evaluate("GetIatProofResult", mapper.iatRequestToMap(requestId))
        );

        if (accessResponseDto.getStatus() == AccessRequestStatusDto.ACCEPTED) {
            accessResponseDto.initialAccessToken(
                    (String) iamClient.registerIam(accessResponseDto.getSubject(), List.of(redirectUri))
                            .get("registration_access_token")
            );
        }
        return accessResponseDto;
    }
}
