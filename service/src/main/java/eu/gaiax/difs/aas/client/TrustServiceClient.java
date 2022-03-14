package eu.gaiax.difs.aas.client;

import java.util.Map;

public interface TrustServiceClient {

    Map<String, Object> evaluate(String policyName, Map<String, Object> bodyParams);

}
