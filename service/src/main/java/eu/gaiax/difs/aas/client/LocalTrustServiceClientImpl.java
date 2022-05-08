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

import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.properties.ServerProperties;
import eu.gaiax.difs.aas.properties.StatusProperties;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;

public class LocalTrustServiceClientImpl implements TrustServiceClient {

    private static final Logger log = LoggerFactory.getLogger("tsclaims");

    private final Map<String, Integer> countdowns = new ConcurrentHashMap<>();
    private final ServerProperties serverProperties;
    private final StatusProperties statusProperties;

    @Value("${aas.tsa.request.count}")
    private int pendingRequestCount;
    
    public LocalTrustServiceClientImpl(ServerProperties serverProperties, StatusProperties statusProperties) {
        this.serverProperties = serverProperties;
        this.statusProperties = statusProperties;
    }
    
    public void setStatusConfig(String policy, AccessRequestStatusDto status) {
        statusProperties.setPolicyStatus(policy, status);
    }
    
    @Override
    public Map<String, Object> evaluate(String policyName, Map<String, Object> bodyParams) {
        Map<String, Object> map = new HashMap<>();
        String requestId = (String) bodyParams.get("requestId");
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        map.put("requestId", requestId);

        if ("GetIatProofInvitation".equals(policyName)) {
            return map;
        }

        if ("GetLoginProofInvitation".equals(policyName)) {
            map.put("link", "uri://" + requestId);
            return map;
        }

        if ("GetLoginProofResult".equals(policyName) || "GetIatProofResult".equals(policyName)) {
            if (isPending(requestId)) {
                map.put("status", PENDING);
            } else {
                AccessRequestStatusDto status = statusProperties.getPolicyStatus(policyName);
                if (status == null) {
                    status = ACCEPTED;
                }
                map.put("status", status);
                if ("GetLoginProofResult".equals(policyName)) {
                    long stamp = System.currentTimeMillis();
                    map.put("name", requestId);
                    map.put("given_name", requestId + ": " + stamp);
                    map.put("family_name", String.valueOf(stamp));
                    map.put("middle_name", null);
                    map.put("preferred_username", requestId + " " + stamp);
                    map.put("gender", stamp % 2 == 0 ? "F" : "M");
                    map.put("birthdate", LocalDate.now().minusYears(21).toString());
                    map.put("updated_at", Instant.now().minusSeconds(86400).getEpochSecond());
                    map.put("email", requestId + "@oidc.ssi");
                    map.put("email_verified", Boolean.TRUE);
                }
            }
            map.put("sub", requestId);
            map.put("iss", serverProperties.getBaseUrl());
            map.put("auth_time", Instant.now().getEpochSecond());
        }

        log.debug("Called local trust service client; policy: {}, params: {}, result: {} ", policyName, bodyParams, map);
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
