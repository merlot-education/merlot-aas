package eu.gaiax.difs.aas.service;

import java.time.LocalTime;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import static java.time.temporal.ChronoUnit.MILLIS;

public class SsiAuthProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthProvider.class);

    @Autowired
    private TrustServiceClient trustServiceClient;

    @Autowired
    private SsiUserService ssiUserService;

    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;

    @Value("${aas.tsa.duration}")
    private long requestingDuration;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);

        GrantedAuthority gr = new SimpleGrantedAuthority("ROLE_ANY");

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(),
                authentication.getCredentials(),
                Collections.singletonList(gr));

        token.setDetails(authentication.getDetails());

        ssiUserService.setUserClaims(getUserClaims((String) authentication.getPrincipal()));

        log.debug("authenticate.exit; returning: {} with name: {}", token, token.getName());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        log.debug("supports.enter; got authentication: {}", authentication);
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    public Map<String, Object> getUserClaims(String requestId) {
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
