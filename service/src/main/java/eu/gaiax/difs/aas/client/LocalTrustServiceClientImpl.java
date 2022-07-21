package eu.gaiax.difs.aas.client;

import java.time.Instant;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.properties.StatusProperties;

import static eu.gaiax.difs.aas.model.TrustServicePolicy.*;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;

public class LocalTrustServiceClientImpl implements TrustServiceClient {

    private static final Logger log = LoggerFactory.getLogger("tsclaims");

    private final Map<String, Integer> countdowns = new ConcurrentHashMap<>();
    private final StatusProperties statusProperties;

    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;
    @Value("${aas.tsa.request.count}")
    private int pendingRequestCount;
    
    public LocalTrustServiceClientImpl(StatusProperties statusProperties) {
        this.statusProperties = statusProperties;
    }
    
    public void setStatusConfig(String policy, AccessRequestStatusDto status) {
        statusProperties.setPolicyStatus(policy, status);
    }
    
    @Override
    public Map<String, Object> evaluate(String policy, Map<String, Object> params) {
        Map<String, Object> map = new HashMap<>();
        String requestId = (String) params.get(PN_REQUEST_ID);
        if (requestId == null && (GET_LOGIN_PROOF_INVITATION.equals(policy) || GET_LOGIN_PROOF_RESULT.equals(policy))) {
            requestId = (String) params.get(IdTokenClaimNames.SUB);
        }
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        map.put(PN_REQUEST_ID, requestId);

        if (GET_IAT_PROOF_INVITATION.equals(policy)) {
            map.put(PN_STATUS, PENDING);
            return map;
        }

        if (GET_LOGIN_PROOF_INVITATION.equals(policy)) {
            map.put(PN_LINK, "uri://" + requestId);
            return map;
        }

        if (GET_LOGIN_PROOF_RESULT.equals(policy) || GET_IAT_PROOF_RESULT.equals(policy)) {
            if (isPending(requestId)) {
                map.put(PN_STATUS, PENDING);
            } else {
                AccessRequestStatusDto status = statusProperties.getPolicyStatus(policy);
                if (status == null) {
                    status = ACCEPTED;
                }
                map.put("status", status);
                if (GET_LOGIN_PROOF_RESULT.equals(policy)) {
                    long stamp = System.currentTimeMillis();
                    map.put(StandardClaimNames.NAME, requestId);
                    map.put(StandardClaimNames.GIVEN_NAME, requestId + ": " + stamp);
                    map.put(StandardClaimNames.FAMILY_NAME, String.valueOf(stamp));
                    map.put(StandardClaimNames.MIDDLE_NAME, "");
                    map.put(StandardClaimNames.PREFERRED_USERNAME, requestId + " " + stamp);
                    map.put(StandardClaimNames.GENDER, stamp % 2 == 0 ? "F" : "M");
                    map.put(StandardClaimNames.BIRTHDATE, LocalDate.now().minusYears(21).toString());
                    map.put(StandardClaimNames.UPDATED_AT, Instant.now().minusSeconds(86400).getEpochSecond());
                    map.put(StandardClaimNames.EMAIL, requestId + "@oidc.ssi");
                    map.put(StandardClaimNames.EMAIL_VERIFIED, Boolean.TRUE);
                }
                if (status == ACCEPTED) {
                    map.put(IdTokenClaimNames.AUTH_TIME, Instant.now().getEpochSecond());
                }
            }
            map.put(IdTokenClaimNames.SUB, requestId);
            map.put(IdTokenClaimNames.ISS, oidcIssuer);
        }

        log.debug("Called local trust service client; policy: {}, params: {}, result: {} ", policy, params, map);
        return map;
    }

    private synchronized boolean isPending(String requestId) {
        int pendingCount = countdowns.getOrDefault(requestId, pendingRequestCount);
        if (pendingCount <= 0) {
            countdowns.remove(requestId);
            return false;
        }
        countdowns.put(requestId, pendingCount - 1);
        return true;
    }
    
}
