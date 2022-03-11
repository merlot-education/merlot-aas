package eu.gaiax.difs.aas.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.web.filter.OncePerRequestFilter;

public class SsiOidcUserInfoEndpointFilter extends OncePerRequestFilter {
    
    private OidcUserInfoEndpointFilter delegate;
    
    public SsiOidcUserInfoEndpointFilter(AuthenticationManager authenticationManager) {
        this.delegate = new OidcUserInfoEndpointFilter(authenticationManager);
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        delegate.doFilter(request, response, filterChain);
    }
}
