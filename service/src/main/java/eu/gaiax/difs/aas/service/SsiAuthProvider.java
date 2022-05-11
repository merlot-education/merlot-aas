package eu.gaiax.difs.aas.service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

public class SsiAuthProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthProvider.class);

    @Autowired
    private SsiBrokerService ssiBrokerService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}; {}", authentication, authentication.getCredentials());

        String requestId = (String) authentication.getPrincipal();
        String authType = (String) authentication.getCredentials();
        boolean required = "OIDC".equals(authType);
        Map<String, Object> claims = ssiBrokerService.getUserClaims(requestId, required);
        if (claims == null) {
            // wrong principal/requestId?
            throw new OAuth2AuthenticationException("loginFailed");
        }
        
        if ("SIOP".equals(authType)) {
            String error = (String) claims.get("error");
            if (error != null) {
                throw new OAuth2AuthenticationException(error);
            }
        }
        
        Set<String> scopes = ssiBrokerService.getUserScopes(requestId);
        List<GrantedAuthority> authorities = scopes.stream().map(s -> new SimpleGrantedAuthority("SCOPE_" + s)).collect(Collectors.toList()); 
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), 
                authentication.getCredentials(), authorities);
        token.setDetails(authentication.getDetails());

        log.debug("authenticate.exit; returning: {} with name: {}", token, token.getName());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        boolean result = authentication.equals(UsernamePasswordAuthenticationToken.class); 
        log.debug("supports.exit; got authentication: {}, returning: {}", authentication, result);
        return result;
    }
}
