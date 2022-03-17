package eu.gaiax.difs.aas.client;

import eu.gaiax.difs.aas.properties.LocalTrustServiceClientProperties;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

public class LocalTrustServiceClientImpl implements TrustServiceClient {

    @Autowired
    private LocalTrustServiceClientProperties config;

    @Override
    public Map<String, Object> evaluate(String policyName, Map<String, Object> bodyParams) {
        Map<String, Object> map = new HashMap<>(Map.copyOf(config.getPolicyMocks().get(policyName)));
        if ("GetLoginProofInvitation".equals(policyName) || "GetIatProofInvitation".equals(policyName)) {
            map.put("requestId", UUID.randomUUID().toString());
        }
        if ("GetLoginProofResult".equals(policyName)) {
            map.put("sub", bodyParams.get("requestId"));
        }
        return map;
    }
}
