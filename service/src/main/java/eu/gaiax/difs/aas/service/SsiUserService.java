package eu.gaiax.difs.aas.service;

import eu.gaiax.difs.aas.client.TrustServiceClient;
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

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class SsiUserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(SsiUserService.class);

    @Autowired
    private TrustServiceClient trustServiceClient;

    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;

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
        while (true) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(
                    "GetLoginProofResult",
                    Collections.singletonMap("requestId", requestId));

            switch ((String) evaluation.get("status")) {
                case "accepted":
                    return evaluation;
                case "pending":
                    delayNextRequest();
                    break;
                case "timeout":
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
