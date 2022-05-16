package eu.gaiax.difs.aas.client;

import java.util.Map;

public interface TrustServiceClient {

    Map<String, Object> evaluate(String policy, Map<String, Object> params);

}
