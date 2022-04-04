package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;

import java.time.LocalTime;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static java.time.temporal.ChronoUnit.MILLIS;

@Service
public class SsiUserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(SsiUserService.class);

    @Autowired
    private TrustServiceClient trustServiceClient;

    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;

    @Value("${aas.tsa.duration}")
    private long requestingDuration;

    private Map<String, Map<String, Object>> userClaimsCache = new ConcurrentHashMap<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("loadUserByUserName.enter; got username: {}", username);

        // TODO: get UserDetails from in-memory store; username = requetsId
        UserDetails ud = User
                .withUsername(username)
                .password("{noop}") //password
                .authorities("ANY")
                .build();

        log.debug("loadUserByUserName.exit; returning: {}", ud);
        return ud;
    }

    public Map<String, Object> getUserClaims(String requestId) {
        if (!userClaimsCache.containsKey(requestId)) {
            return userClaimsCache.put(requestId, loadUserClaims(requestId));
        }
        else {
            return userClaimsCache.get(requestId);
        }
    }

    private Map<String, Object> loadUserClaims(String requestId) {
        LocalTime requestingStart = LocalTime.now();
        LocalTime durationRestriction = requestingStart.plusNanos(1_000_000 * requestingDuration);

        while (LocalTime.now().isBefore(durationRestriction)) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(
                    "GetLoginProofResult",
                    Collections.singletonMap("requestId", requestId));

            if (evaluation.get("status") == null || !(evaluation.get("status") instanceof AccessRequestStatusDto)) {
                log.error("Exception during call Evaluate of TrustServiceClient, response status is not specified: {}", evaluation.get("status"));
                throw new OAuth2AuthenticationException("Login failed");
            }

            switch ((AccessRequestStatusDto) evaluation.get("status")) {
                case ACCEPTED:
                    return evaluation;
                case PENDING:
                    delayNextRequest();
                    break;
                case REJECTED:
                    throw new OAuth2AuthenticationException("Login rejected");
                case TIMED_OUT:
                    log.error("Exception during call Evaluate of TrustServiceClient, response status: {}", evaluation.get("status"));
                    throw new OAuth2AuthenticationException("Login expired");
            }
        }

        log.error("Time for calling TrustServiceClient expired, time spent: {} ms", requestingStart.until(LocalTime.now(), MILLIS));
        throw new OAuth2AuthenticationException("Login expired");
    }

    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(millisecondsToDelay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
