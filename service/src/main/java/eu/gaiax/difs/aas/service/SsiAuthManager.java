package eu.gaiax.difs.aas.service;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class SsiAuthManager implements AuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthManager.class);
    
    @Autowired
    private SsiBrokerService ssiBrokerService;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);
        String requestId = null;
        List<String> scopes = null;
        if (authentication instanceof OidcUserInfoAuthenticationToken) {
            requestId = ((JwtAuthenticationToken) authentication.getPrincipal()).getToken().getSubject();
            scopes = ((JwtAuthenticationToken) authentication.getPrincipal()).getToken().getClaimAsStringList("scope");
        } else if (authentication instanceof BearerTokenAuthenticationToken) {
            requestId = ((BearerTokenAuthenticationToken) authentication).getName(); // .getToken();
            scopes = Collections.emptyList();
        }
        Map<String, Object> additionalParams = ssiBrokerService.getAdditionalParameters(requestId);
        boolean needAuthTime = additionalParams != null && additionalParams.get("max_age") != null; //oar.getAdditionalParameters().get("auth_time") != null; 

        int ccnt = 0, pcnt = 0;
        OidcUserInfo.Builder uiBuilder = OidcUserInfo.builder();
        Map<String, Object> userDetails = ssiBrokerService.getUserClaims(requestId, false, scopes); //required?
        if (userDetails != null) {
            for (Map.Entry<String, Object> e: userDetails.entrySet()) {
                if (needAuthTime || !e.getKey().equals("auth_time")) {
                    uiBuilder.claim(e.getKey(), e.getValue());
                    pcnt++;
                }
                ccnt++;
            }
        }
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, uiBuilder.build());
        log.debug("authenticate.exit; added {} claims out of {} for subject: {}", pcnt, ccnt, requestId);
        return token;
    }

}
