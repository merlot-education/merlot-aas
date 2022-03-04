package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;

public class SsiAuthManager implements AuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthManager.class);
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, 
                OidcUserInfo.builder().name("user").email("test@test.com").subject("user").build());
        return token;
    }

}
