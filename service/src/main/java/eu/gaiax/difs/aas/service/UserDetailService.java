package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class UserDetailService {

    private final TrustServiceClient trustServiceClient;

    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;

    public UserDetailService(TrustServiceClient trustServiceClient) {
        this.trustServiceClient = trustServiceClient;
    }

    public Map<String, Object> getUserClaims(String requestId) {
        while (true) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(
                    "GetLoginProofResult",
                    Collections.singletonMap("requestId", requestId));

            if ("accepted".equals(evaluation.get("status"))) {
                return evaluation;
            }

            if ("pending".equals(evaluation.get("status"))) {
                delayNextRequest();
            }

            if ("timeout".equals(evaluation.get("status"))) {
                throw new OAuth2AuthenticationException("Exception during call evaluate of TrustServiceClient");
            }
        }
    }

    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(millisecondsToDelay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

}
