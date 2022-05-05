package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class SsiAuthManager implements AuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthManager.class);
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);
        String subject = "user";
        if (authentication instanceof OidcUserInfoAuthenticationToken) {
            subject = ((JwtAuthenticationToken) authentication.getPrincipal()).getToken().getSubject(); 
        } else if (authentication instanceof BearerTokenAuthenticationToken) {
            subject = ((BearerTokenAuthenticationToken) authentication).getName(); // .getToken();
        }
        // TODO: get claims from UserDetailService by requestId..?
        // get requested scopes from token, then use claims which corresponds to requested scopes only..
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, 
                OidcUserInfo.builder().name(subject).email(subject + "@oidc.ssi").subject(subject).build());
        log.debug("authenticate.exit; returning: {} for subject: {}", token, subject);
        return token;
    }

}
