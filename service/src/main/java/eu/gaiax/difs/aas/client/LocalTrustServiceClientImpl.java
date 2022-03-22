package eu.gaiax.difs.aas.client;

import eu.gaiax.difs.aas.properties.LocalTrustServiceClientProperties;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;

public class LocalTrustServiceClientImpl implements TrustServiceClient {

    @Autowired
    private LocalTrustServiceClientProperties config;

    // TODO: replace with <requestId, count> map for multi-threaded tests
    private int sendAcceptedStatusCountdown = 1;

    @Override
    public Map<String, Object> evaluate(String policyName, Map<String, Object> bodyParams) {
        Map<String, Object> map = new HashMap<>(Map.copyOf(config.getPolicyMocks().get(policyName)));

        if ("GetLoginProofInvitation".equals(policyName) || "GetIatProofInvitation".equals(policyName)) {
            map.put("requestId", UUID.randomUUID().toString());
        }

        if ("GetLoginProofResult".equals(policyName)) {
            String requestId = (String) bodyParams.get("requestId");
            map.put("sub", requestId);
            map.put("email", requestId + "@oidc.ssi");
            map.put("name", requestId);
        }

        if ("GetLoginProofResult".equals(policyName) || "GetIatProofResult".equals(policyName)) {
            if (sendAcceptedStatusCountdown-- > 0) {
                map.put("status", PENDING);
            } else {
                map.put("status", ACCEPTED);
                sendAcceptedStatusCountdown = 1;
            }
        }

        return map;
    }
}
