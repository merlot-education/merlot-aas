package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SsiUserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(SsiUserService.class);

    private Map<String, Object> userClaims;

    public Map<String, Object> getUserClaims() {
        return userClaims;
    }

    public void setUserClaims(Map<String, Object> userClaims) {
        this.userClaims = userClaims;
    }

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
}
