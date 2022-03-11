package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class SsiUserService implements UserDetailsService { 
    
    private static final Logger log = LoggerFactory.getLogger(SsiUserService.class);
    
    // TODO: we'll need in-memory store where we'll store user claims (UserDetails?) per requestId 
    // we can use HashMap for this, or we can investigate how InMemory.. SS classes are implemented, 
    // may be we could use them

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("loadUserByUserName.enter; got username: {}", username);
        // TODO: get UserDetails from in-memory store; username = requetsId
        UserDetails ud = User.withUsername(username)
                .password("{noop}") //password
                .authorities("ANY")
                .build();
        log.debug("loadUserByUserName.exit; returning: {}", ud);
        return ud;
    }

}
