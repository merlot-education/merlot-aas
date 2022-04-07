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
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import eu.gaiax.difs.aas.service.SsiAuthManager;

/**
 * The Spring Security config.
 */
@Configuration
public class AuthorizationServerConfig { 
    
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    
    @Value("${aas.iam.client-id}")
    private String clientId;

    @Value("${aas.iam.client-secret}")
    private String clientSecret;

    @Value("${aas.iam.redirect-uri}")
    private String redirectUri;

//    @Autowired
//    private ApplicationEventPublisher publisher;
//
//    @Bean
//    public AuthenticationEventPublisher authenticationEventPublisher() {
//        final Properties properties = new Properties();
//        properties.put(
//                OAuth2AuthenticationException.class.getCanonicalName(),
//                AuthenticationFailureBadCredentialsEvent.class.getCanonicalName());
//
//        final DefaultAuthenticationEventPublisher eventPublisher = new DefaultAuthenticationEventPublisher(publisher);
//
//        eventPublisher.setAdditionalExceptionMappings(properties);
//
//        return eventPublisher;
//    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applySecurity(http);
        http.formLogin()
                .loginPage("/ssi/login")
                .loginProcessingUrl("/ssi/login") //TODO: Viktor: not working POST (should trigger SsiAuthProvider.auth method)
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
                .apply(authorizationServerConfigurer);
    }

    private ObjectPostProcessor<Object> ssiObjectPostProcessor() {
        return new ObjectPostProcessor<>() {
            @Override
            @SuppressWarnings("unchecked")
            public <O> O postProcess(O object) {
                if (object instanceof OidcProviderConfigurationEndpointFilter) {
                    return (O) new SsiOidcProviderConfigurationEndpointFilter(providerSettings());
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
        RegisteredClient reClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret) 
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                //.scopes(c -> c.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)))
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        // my be we'll use it later on..
                        //.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(reClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer(issuerUri)
                // could be added later. but ClientRegistrationEndpoint is not present in OidcProviderConfiguration (yet?)
                // so it is not clear, how should we expose it
                //.oidcClientRegistrationEndpoint("/clients/registration")
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
