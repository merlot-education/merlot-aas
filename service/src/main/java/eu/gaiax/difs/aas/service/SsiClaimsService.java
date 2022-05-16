package eu.gaiax.difs.aas.service;

import static eu.gaiax.difs.aas.model.SsiAuthErrorCodes.*;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;

import java.time.LocalTime;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.client.TrustServicePolicy;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import lombok.RequiredArgsConstructor;

public abstract class SsiClaimsService {
    
    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;
    @Value("${aas.tsa.duration}")
    private long requestingDuration;

    protected final TrustServiceClient trustServiceClient;
    
    public SsiClaimsService(TrustServiceClient trustServiceClient) {
        this.trustServiceClient = trustServiceClient;
    }
    
    protected Map<String, Object> loadTrustedClaims(TrustServicePolicy policy, String requestId) {
        LocalTime requestingStart = LocalTime.now();
        LocalTime durationRestriction = requestingStart.plusNanos(1_000_000 * requestingDuration);

        while (LocalTime.now().isBefore(durationRestriction)) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(policy, Collections.singletonMap("requestId", requestId));

            Object o = evaluation.get("status");
            if (o == null || !(o instanceof AccessRequestStatusDto)) {
                //log.error("loadTrustedClaims; unknown response status: {}", o);
                throw new OAuth2AuthenticationException(SERVER_ERROR);
            }

            switch ((AccessRequestStatusDto) o) {
                case ACCEPTED:
                    return evaluation;
                case PENDING:
                    delayNextRequest();
                    break;
                case REJECTED:
                    throw new OAuth2AuthenticationException(LOGIN_REJECTED);
                case TIMED_OUT:
                    throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
            }
        }

        //log.error("loadTrustedClaims; Time for calling TrustServiceClient expired, time spent: {} ms", requestingStart.until(LocalTime.now(), MILLIS));
        throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
    }

    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(millisecondsToDelay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
    

}
