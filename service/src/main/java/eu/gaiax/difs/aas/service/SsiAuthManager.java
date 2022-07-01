package eu.gaiax.difs.aas.service;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
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
        log.debug("authenticate; subject: {}, scopes: {}", requestId, scopes);
        
        boolean needAuthTime = false;
        Set<String> additionalClaims;
        Map<String, Object> additionalParams = ssiBrokerService.getAdditionalParameters(requestId);
        if (additionalParams != null) {
            additionalClaims = new HashSet<>();
            Map<String, Object> userInfo = (Map<String, Object>) additionalParams.get("userinfo");
            if (userInfo != null) {
                additionalClaims.addAll(userInfo.keySet());
            }
            if (additionalParams.get(IdTokenClaimNames.AUTH_TIME) != null || additionalParams.get("max_age") != null) {
                additionalClaims.add(IdTokenClaimNames.AUTH_TIME);
                needAuthTime = true;
            }
        } else {
            additionalClaims = Collections.emptySet();
        }

        int cnt = 0;
        OidcUserInfo.Builder uiBuilder = OidcUserInfo.builder();
        Map<String, Object> userDetails = ssiBrokerService.getUserClaims(requestId, false, scopes, additionalClaims); //required?
        if (userDetails != null) {
            for (Map.Entry<String, Object> e: userDetails.entrySet()) {
                if (!IdTokenClaimNames.AUTH_TIME.equals(e.getKey()) || needAuthTime) {
                    uiBuilder.claim(e.getKey(), e.getValue());
                    cnt++;
                }
            }
        }
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, uiBuilder.build());
        log.debug("authenticate.exit; added {} claims for subject: {}", cnt, requestId);
        return token;
    }

}
