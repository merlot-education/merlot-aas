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

import eu.gaiax.difs.aas.properties.ScopeProperties;

public class SsiAuthManager implements AuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthManager.class);
    
    @Autowired
    private SsiUserService ssiUserService;
    @Autowired
    private ScopeProperties scopeProperties;
    
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

        OidcUserInfo.Builder uiBuilder = OidcUserInfo.builder();
        Map<String, Object> userDetails = ssiUserService.getUserClaims(requestId, false);
        // get requested scopes from token, then use claims which corresponds to requested scopes only..
        if (userDetails != null) {
            for (String scope: scopes) {
                List<String> claims = scopeProperties.getScopes().get(scope);
                for (String claim: claims) {
                    Object value = userDetails.get(claim);
                    if (value != null) {
                        uiBuilder.claim(claim, value);
                    }
                }
            }
        }
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, uiBuilder.build());
        log.debug("authenticate.exit; returning userInfo: {} for subject: {}", token.getUserInfo().getClaims(), requestId);
        return token;
    }

}

//{sub=5a083275-8403-4fdb-af27-f6e27408e12e, aud=[aas-app-oidc], nbf=2022-05-05T18:20:56Z, scope=["openid"], iss=http://auth-server:9000, exp=2022-05-05T18:30:56Z, iat=2022-05-05T18:20:56Z}