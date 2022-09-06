package eu.gaiax.difs.aas.config;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import eu.gaiax.difs.aas.properties.ScopeProperties;

public final class SsiOidcProviderConfigurationEndpointFilter extends OncePerRequestFilter {

    /**
     * The default endpoint {@code URI} for OpenID Provider Configuration requests.
     */
    private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

    private final ProviderSettings providerSettings;
    private final ScopeProperties scopeProperties;
    private final RequestMatcher requestMatcher;
    private final OidcProviderConfigurationHttpMessageConverter providerConfigurationHttpMessageConverter =
            new OidcProviderConfigurationHttpMessageConverter();

    public SsiOidcProviderConfigurationEndpointFilter(ProviderSettings providerSettings, ScopeProperties scopeProperties) {
        Assert.notNull(providerSettings, "providerSettings cannot be null");
        this.providerSettings = providerSettings;
        this.scopeProperties = scopeProperties;
        this.requestMatcher = new AntPathRequestMatcher(
                DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI,
                HttpMethod.GET.name()
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String issuer = ProviderContextHolder.getProviderContext().getIssuer();

        OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
                // issuer
                .issuer(issuer)
                // authorization_endpoint
                .authorizationEndpoint(asUrl(issuer, this.providerSettings.getAuthorizationEndpoint()))
                // token_endpoint
                .tokenEndpoint(asUrl(issuer, this.providerSettings.getTokenEndpoint()))
                // jwks_uri
                .jwkSetUrl(asUrl(issuer, this.providerSettings.getJwkSetEndpoint()))
                // userinfo_endpoint
                .userInfoEndpoint(asUrl(issuer, this.providerSettings.getOidcUserInfoEndpoint()))
                // token_endpoint_auth_methods_supported
                .tokenEndpointAuthenticationMethods(clientAuthenticationMethods())
                // response_types_supported
                .responseTypes(authResponseTypes())
                // grant_types_supported
                .grantTypes(authGrantTypes())
                // subject_types_supported
                .subjectType("public")
                // id_token_signing_alg_values_supported
                .idTokenSigningAlgorithms(signingAlgorithms())
                // scopes_supported
                .scopes(oidcScopes())
                .claims(claims())
                .claim("end_session_endpoint", this.providerSettings.getIssuer() + "/logout")
                .build();

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.providerConfigurationHttpMessageConverter.write(providerConfiguration, MediaType.APPLICATION_JSON, httpResponse);
    }

    private String asUrl(String issuer, String endpoint) {
        return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
    }

    private Consumer<List<String>> clientAuthenticationMethods() {
        return (authenticationMethods) -> authenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
    }

    private Consumer<List<String>> oidcScopes() {
        return (oidcScopes) -> oidcScopes.addAll(scopeProperties.getScopes().keySet());
    }

    private Consumer<List<String>> authGrantTypes() {
        return (authorizationGrantTypes) -> authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
    }

    private Consumer<List<String>> authResponseTypes() {
        return (authResponseTypes) -> authResponseTypes.add(OAuth2AuthorizationResponseType.CODE.getValue());
    }

    private Consumer<List<String>> signingAlgorithms() {
        return (signingAlgorithms) -> signingAlgorithms.add(SignatureAlgorithm.RS256.getName());
    }

    private Consumer<Map<String, Object>> claims() {
        List<String> supportedClaims = scopeProperties.getScopes()
                .values().stream().flatMap(List::stream)
                .distinct().sorted()
                .collect(Collectors.toList());

        return (claims) -> {
            claims.put("userinfo_signing_alg_values_supported", List.of("RS256"));
            claims.put("display_values_supported", List.of("page"));
            claims.put("claims_supported", supportedClaims);
            claims.put("claims_locales_supported", List.of("en"));
            claims.put("ui_locales_supported", List.of("en", "de", "fr", "ru", "sk"));
        };
    }

}
