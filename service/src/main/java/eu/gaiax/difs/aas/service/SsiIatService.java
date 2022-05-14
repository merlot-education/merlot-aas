package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.IamClient;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.client.TrustServicePolicy;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class SsiIatService extends SsiClaimsService {

    private static final Logger log = LoggerFactory.getLogger(SsiIatService.class);

    private final Map<String, Map<String, Object>> iatCache = new ConcurrentHashMap<>();
    
    private final IamClient iamClient;
    private final ClientsProperties clientsProperties;

    public SsiIatService(TrustServiceClient trustServiceClient, IamClient iamClient, ClientsProperties clientsProperties) {
        super(trustServiceClient);
        this.iamClient = iamClient;
        this.clientsProperties = clientsProperties;
    }

    public AccessResponseDto evaluateIatProofInvitation(AccessRequestDto accessRequestDto) {
        log.debug("evaluateIatProofInvitation.enter; got request: {}", accessRequestDto);
        Map<String, Object> evalRequest = iatRequestToMap(accessRequestDto);
        Map<String, Object> evalResponse = trustServiceClient.evaluate(TrustServicePolicy.GET_IAT_PROOF_INVITATION, evalRequest);
        String requestId = (String) evalResponse.get("requestId");
        initIatRequest(requestId.toString(), evalRequest);
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
    
    private void initIatRequest(String requestId, Map<String, Object> evalRequest) {
        iatCache.put(requestId,  evalRequest);
    }

    public AccessResponseDto evaluateIatProofResult(String requestId) {
        log.debug("evaluateIatProofResult.enter; got request: {}", requestId);
        Map<String, Object> evalRequest =  Collections.singletonMap("requestId", requestId);
        Map<String, Object> evalResponse = trustServiceClient.evaluate(TrustServicePolicy.GET_IAT_PROOF_RESULT, evalRequest);
        AccessResponseDto accessResponseDto = mapToIatAccessResponse(evalResponse);

        if (accessResponseDto.getStatus() == AccessRequestStatusDto.ACCEPTED) {
            Map<String, Object> regResponse = iamClient.registerIam(accessResponseDto.getSubject(), List.of(clientsProperties.getOidc().getRedirectUri()));
            String iat = (String) regResponse.get("registration_access_token");
            accessResponseDto.setInitialAccessToken(iat);
        }
        log.debug("evaluateIatProofResult.exit; returning: {}", accessResponseDto);
        return accessResponseDto;
    }

    public AccessResponseDto getIatProofResult(String requestId) {
        log.debug("getIatProofResult.enter; got request: {}", requestId);
        Map<String, Object> iatClaims = iatCache.get(requestId); 
        AccessResponseDto accessResponseDto = mapToIatAccessResponse(iatClaims);
        if (iatClaims == null) {
            iatClaims = loadTrustedClaims(TrustServicePolicy.GET_IAT_PROOF_RESULT, requestId);
            //addAuthData(requestId, iatClaims);
            Map<String, Object> regResponse = iamClient.registerIam(accessResponseDto.getSubject(), List.of(clientsProperties.getOidc().getRedirectUri()));
            String iat = (String) regResponse.get("registration_access_token");
            accessResponseDto.setInitialAccessToken(iat);
        }
        log.debug("getIatProofResult.exit; returning: {}", accessResponseDto);
        return accessResponseDto;
    }
    
// got registration response: {redirect_uris=[http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint], 
// token_endpoint_auth_method=client_secret_basic, grant_types=[authorization_code], response_types=[code, none], client_id=557bdca7-0b49-477b-bc67-f9d81a82a245, 
// client_secret=NyAun7G2Htuz2EuSSsvoXetOi2FqjRO1, client_name=http://auth-server:9000, scope=address phone offline_access microprofile-jwt, subject_type=public, 
// request_uris=[], tls_client_certificate_bound_access_tokens=false, client_id_issued_at=1652273791, client_secret_expires_at=0, 
// registration_client_uri=http://key-server:8080/realms/gaia-x/clients-registrations/openid-connect/557bdca7-0b49-477b-bc67-f9d81a82a245, 
// registration_access_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmMGUzNzY0Mi0zYWIzLTQ2NWItODcyYi1kNmZkMTljOTcwOWQifQ.eyJleHAiOjAsImlhdCI6MTY1MjI3Mzc5MSwianRpIjoiZmUxMmUwMmItNGZlOC00ZTg5LWExMzUtMjY4ZGYzZjNiZDNhIiwiaXNzIjoiaHR0cDovL2tleS1zZXJ2ZXI6ODA4MC9yZWFsbXMvZ2FpYS14IiwiYXVkIjoiaHR0cDovL2tleS1zZXJ2ZXI6ODA4MC9yZWFsbXMvZ2FpYS14IiwidHlwIjoiUmVnaXN0cmF0aW9uQWNjZXNzVG9rZW4iLCJyZWdpc3RyYXRpb25fYXV0aCI6ImF1dGhlbnRpY2F0ZWQifQ.JxLgfxoDY62FLP6A58JA1arPF2tB1yQO6w0iPhD8Txw, 
// backchannel_logout_session_required=false, require_pushed_authorization_requests=false}
    
    private AccessResponseDto mapToIatAccessResponse(Map<String, Object> map) {
        String requestId = (String) map.get("requestId");
        if (requestId == null) {
            // throw error?
            log.info("mapToIatAccessResponse; no requestId found in IAT response: {}", map);
            return null;
        }

        String entity = null;
        String subject = null;
        Set<String> scopes = null;
        Map<String, Object> iatRequest = iatCache.get(requestId);
        if (iatRequest == null) {
            log.info("mapToIatAccessResponse; no data found for requestId: {}", requestId);
        } else {
            entity = (String) iatRequest.get("iss");
            subject = (String) iatRequest.get("sub");
            scopes = (Set<String>) iatRequest.get("scope");
        }
        // update request with new data?
        // remove request after acceptance?

        return new AccessResponseDto().subject(entity)
                .entity(new ServiceAccessScopeDto()
                        .scope(scopes == null ? null : scopes.stream().collect(Collectors.joining(" ")))
                        .did(subject)) 
                .status((AccessRequestStatusDto) map.getOrDefault("status", null))
                .requestId(requestId);
                //.initialAccessToken((String) map.getOrDefault("iat", null))
                //.policyEvaluationResult(map.getOrDefault("policyEvaluationResult", null));
    }

}
