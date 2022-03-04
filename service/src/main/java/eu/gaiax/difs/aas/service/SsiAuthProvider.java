package eu.gaiax.difs.aas.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SsiAuthProvider implements AuthenticationProvider {
    
    private static final Logger log = LoggerFactory.getLogger(SsiAuthProvider.class);
    

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);
        GrantedAuthority gr = new SimpleGrantedAuthority("ROLE_ADMIN");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", //authentication.getPrincipal(), 
                authentication.getCredentials(), Collections.singletonList(gr));
        token.setDetails(authentication.getDetails());
        //WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        //Map<String, String> claims = new HashMap<>();
        //claims.put("email", "test@test.com");
        //claims.put("username", "user");
        //token.setDetails(claims);
        log.debug("authenticate.exit; returning: {} with name: {}", token, token.getName());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        log.debug("supports.enter; got authentication: {}", authentication);
        return true; //authentication.equals(ExternalServiceAuthenticationToken.class);
    }
    

}

