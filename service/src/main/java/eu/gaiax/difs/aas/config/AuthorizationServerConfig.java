/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.gaiax.difs.aas.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import eu.gaiax.difs.aas.properties.ClientsProperties;
import eu.gaiax.difs.aas.properties.ClientsProperties.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import eu.gaiax.difs.aas.properties.ScopeProperties;
import eu.gaiax.difs.aas.properties.ServerProperties;
import eu.gaiax.difs.aas.service.SsiAuthManager;

/**
 * The Spring Security config.
 */
@Configuration
public class AuthorizationServerConfig {

    @Value("${aas.id-token.ttl}")
    private Duration ttl;
    @Value("${aas.jwk.length}")
    private int jwkLength;
    @Value("${aas.jwk.secret}")
    private String jwkSecret;
    
    private final ScopeProperties scopeProperties;
    private final ClientsProperties clientsProperties;
    private final ServerProperties serverProperties;
    
    @Autowired
    public AuthorizationServerConfig(ScopeProperties scopeProperties, ClientsProperties clientsProperties, ServerProperties serverProperties) {
        this.scopeProperties = scopeProperties;
        this.clientsProperties = clientsProperties;
        this.serverProperties = serverProperties;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applySecurity(http);
        http.formLogin()
                .loginPage("/ssi/login")
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

    private void applySecurity(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();

        authorizationServerConfigurer.addObjectPostProcessor(ssiObjectPostProcessor());

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .objectPostProcessor(ssiObjectPostProcessor())
                .apply(authorizationServerConfigurer)
                .and()
                .addFilterAfter(new SsiOAuth2ValidationFilter(), LogoutFilter.class)
                ;
    }

    //CsrfFilter
    //LogoutFilter
    //OAuth2AuthorizationEndpointFilter    
    
    private ObjectPostProcessor<Object> ssiObjectPostProcessor() {
        return new ObjectPostProcessor<>() {
            @Override
            @SuppressWarnings("unchecked")
            public <O> O postProcess(O object) {
                if (object instanceof OidcProviderConfigurationEndpointFilter) {
                    return (O) new SsiOidcProviderConfigurationEndpointFilter(providerSettings(), scopeProperties);
                } else if (object instanceof OidcUserInfoEndpointFilter) {
                    return (O) new SsiOidcUserInfoEndpointFilter(authenticationManager());
                }
                return object;
            }
        };
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new SsiAuthManager();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
                prepareClient(clientsProperties.getOidc()),
                prepareClient(clientsProperties.getSiop()));
    }

    private RegisteredClient prepareClient(ClientProperties client) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.getId())
                .clientSecret(client.getSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(client.getRedirectUri())
                .scopes(c -> c.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)))
                .clientSettings(ClientSettings.builder()
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        // maybe we'll use it later on..
                        //.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(ttl)
                        .build())
                .build();
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer(serverProperties.getBaseUrl())
                // could be added later. but ClientRegistrationEndpoint is not present in OidcProviderConfiguration (yet?)
                // so it is not clear, how should we expose it
                //.oidcClientRegistrationEndpoint("/clients/registration")
                .build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) throws JOSEException {
        JWK jwk = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null).get(0);
        //OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault(); 
        OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(serverProperties.getBaseUrl());
        RSAPublicKey publicKey = jwk.toRSAKey().toRSAPublicKey();
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        jwtDecoder.setJwtValidator(jwtValidator);
        return jwtDecoder;
    }
    
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(jwkSecret)
                .build();
    }

    private KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(jwkLength);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
