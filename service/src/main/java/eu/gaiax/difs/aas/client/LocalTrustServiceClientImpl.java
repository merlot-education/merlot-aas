package eu.gaiax.difs.aas.client;

import eu.gaiax.difs.aas.properties.LocalTrustServiceClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class LocalTrustServiceClientImpl implements TrustServiceClient {

    @Autowired
    private LocalTrustServiceClientProperties config;

    @Override
    public Map<String, Object> evaluate(String policyname, Map<String, Object> bodyParams) {
        return config.getPolicyMocks().get(policyname);
    }
}
