package eu.gaiax.difs.aas.client;

import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
public class LocalTrustServiceClientImpl implements TrustServiceClient {

    private Map<String, Object> config;

    @Override
    public Map<String, Object> evaluate(String policyname, Map<String, Object> bodyParams) {
        // check params passed and return response, dependent on the params and local config
        return Collections.emptyMap();
    }
}
