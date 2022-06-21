package eu.gaiax.difs.aas.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.Assert;

//import com.hazelcast.config.IndexType;
//import com.hazelcast.core.Hazelcast;
//import com.hazelcast.core.HazelcastInstance;
//import com.hazelcast.map.IMap;

public class SsiAuthorizationService implements OAuth2AuthorizationService {
    
    private static final Logger log = LoggerFactory.getLogger(SsiAuthorizationService.class);
    
    private static final int maxInitializedAuthorizations = 100;

    /*
     * Stores "initialized" (uncompleted) authorizations, where an access token has not yet been granted.
     * This state occurs with the authorization_code grant flow during the user consent step OR
     * when the code is returned in the authorization response but the access token request is not yet initiated.
     */
    private final Map<String, OAuth2Authorization> initializedAuthorizations;

    /*
     * Stores "completed" authorizations, where an access token has been granted.
     */
    private final Map<String, OAuth2Authorization> authorizations;
    
    private final Map<String, String> codes;

    /**
     * Constructs an {@code SsiAuthorizationService}.
     */
    public SsiAuthorizationService(int maxSize) {
        //HazelcastInstance hzi = Hazelcast.getOrCreateHazelcastInstance();
        //IMap<String, OAuth2Authorization> initialized = hzi.getMap("initialized");
        //initialized.addIndex(IndexType.HASH, null);
        this.initializedAuthorizations = new ConcurrentHashMap<>(); //Collections.synchronizedMap(new MaxSizeHashMap<>(maxSize)); initialized; 
        this.authorizations = new ConcurrentHashMap<>();
        this.codes = new ConcurrentHashMap<>();
    }

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
     *
     * @param authorizations the authorization(s)
     */
    public SsiAuthorizationService(List<OAuth2Authorization> authorizations) {
        this(maxInitializedAuthorizations);
        Assert.notNull(authorizations, "authorizations cannot be null");
        authorizations.forEach(authorization -> {
            Assert.notNull(authorization, "authorization cannot be null");
            Assert.isTrue(!this.authorizations.containsKey(authorization.getId()),
                    "The authorization must be unique. Found duplicate identifier: " + authorization.getId());
            this.authorizations.put(authorization.getId(), authorization);
        });
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            codes.put(authorizationCode.getToken().getTokenValue(), authorization.getId());
        }
        if (isComplete(authorization)) {
            this.authorizations.put(authorization.getId(), authorization);
        } else {
            this.initializedAuthorizations.put(authorization.getId(), authorization);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        log.debug("remove.enter; got authorization: {}", authorization);
        boolean removed;
        if (isComplete(authorization)) {
            removed = this.authorizations.remove(authorization.getId(), authorization);
        } else {
            removed = this.initializedAuthorizations.remove(authorization.getId(), authorization);
        }
        if (removed) {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                    authorization.getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null) {
                codes.remove(authorizationCode.getToken().getTokenValue());
            }
        }
        log.debug("remove.exit; removed: {}", removed);
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        OAuth2Authorization authorization = this.authorizations.get(id);
        return authorization != null ?
                authorization :
                this.initializedAuthorizations.get(id);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        log.debug("findByToken.enter; got token: {}, type: {}", token, tokenType == null ? null : tokenType.getValue());
        //try {
        //    throw new Exception("debug");
        //} catch (Exception ex) {
        //    ex.printStackTrace();
        //}
        if ("code".equals(tokenType.getValue())) {
            String id = codes.get(token);
            if (id != null) {
                OAuth2Authorization authorization = findById(id);
                log.debug("findByToken.exit; returning codes: {}", authorization);
                return authorization;
            }
        }
        
        for (OAuth2Authorization authorization : this.authorizations.values()) {
            if (hasToken(authorization, token, tokenType)) {
                log.debug("findByToken.exit; returning authorized: {}", authorization);
                return authorization;
            }
        }
        //List<OAuth2Authorization> values = new ArrayList<>(this.initializedAuthorizations.values());
        Collection<OAuth2Authorization> values = this.initializedAuthorizations.values();
        for (OAuth2Authorization authorization : values) {
            if (hasToken(authorization, token, tokenType)) {
                log.debug("findByToken.exit; returning initialized: {}", authorization);
                return authorization;
            }
        }
        log.info("findByToken.exit; no authorization found for token: {}, type: {}; authorized size: {}, initialized size: {}, ", 
                token, tokenType == null ? null : tokenType.getValue(), authorizations.size(), initializedAuthorizations.size());
        return null;
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesState(authorization, token) ||
                    matchesAuthorizationCode(authorization, token) ||
                    matchesAccessToken(authorization, token) ||
                    matchesRefreshToken(authorization, token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return matchesState(authorization, token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return matchesAuthorizationCode(authorization, token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return matchesAccessToken(authorization, token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return matchesRefreshToken(authorization, token);
        }
        return false;
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }

    private static final class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
        private final int maxSize;

        private MaxSizeHashMap(int maxSize) {
            this.maxSize = maxSize;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > this.maxSize;
        }

    }

}
