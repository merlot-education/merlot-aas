package eu.gaiax.difs.aas.client;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;

public class LocalTrustServiceClientImpl implements TrustServiceClient {

    // TODO: replace with <requestId, count> map for multi-threaded tests
    private int sendAcceptedStatusCountdown = 1;

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
            if (sendAcceptedStatusCountdown-- > 0) {
                map.put("status", PENDING);
            } else {
                map.put("status", PENDING);
                sendAcceptedStatusCountdown = 1;
                if ("GetLoginProofResult".equals(policyName) ) {
                    map.put("email", requestId + "@oidc.ssi");
                    map.put("name", requestId);
                }
            }
            map.put("sub", requestId);
            map.put("iss", "test-iss");
            map.put("claim1", "test-claim1");
       }

        return map;
    }
}
