package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {

    private final TrustServiceClient client;

    @Value("${aas.iat}")
    private String iat;

    @Autowired
    public AuthService(TrustServiceClient client) {
        this.client = client;
    }

    public Map<String, Object> evaluate(String policy, Map<String, Object> params) {
        Map<String, Object> evaluation = client.evaluate(policy, params);

        if ("GetIatProofResult".equals(policy) && "accepted".equals(evaluation.get("status"))) {
            evaluation.put("iat", iat);
        }

        return evaluation;
    }

}
