package eu.gaiax.difs.aas.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
//import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
//import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
//import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.Assert;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.RemovalListener;


public class SsiAuthorizationService implements OAuth2AuthorizationService, RemovalListener<String, OAuth2Authorization> {
    
    private static final Logger log = LoggerFactory.getLogger(SsiAuthorizationService.class);
    
    private final int cacheSize;
    private final Duration ttl;
    
    private Cache<String, OAuth2Authorization> authorizations;

    private final Map<String, String> codes;

    public SsiAuthorizationService(int cacheSize, Duration ttl) {
        this.cacheSize = cacheSize;
        this.ttl = ttl;
        this.codes = new ConcurrentHashMap<>();
    }
    
    @PostConstruct
    public void init() {
        Caffeine<Object, Object> cache = Caffeine.newBuilder().expireAfterAccess(ttl); 
        if (cacheSize > 0) {
            cache = cache.maximumSize(cacheSize);
        } 
        authorizations = cache.removalListener(this).build(); 
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            codes.put(authorizationCode.getToken().getTokenValue(), authorization.getId());
        }
        this.authorizations.put(authorization.getId(), authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        log.debug("remove.enter; got authorization: {}", authorization);
        this.authorizations.invalidate(authorization.getId());
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizations.getIfPresent(id);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        String tkType = tokenType == null ? null : tokenType.getValue();
        log.debug("findByToken.enter; got token: {}, type: {}", token, tkType);
        if ("code".equals(tokenType.getValue())) {
            String id = codes.get(token);
            if (id != null) {
                OAuth2Authorization authorization = findById(id);
                log.debug("findByToken.exit; returning codes: {}", authorization);
                return authorization;
            }
        }
        
        //for (OAuth2Authorization authorization : this.authorizations.values()) {
        //    if (hasToken(authorization, token, tokenType)) {
        //        log.debug("findByToken.exit; returning authorized: {}", authorization);
        //        return authorization;
        //    }
        //}
        //List<OAuth2Authorization> values = new ArrayList<>(this.initializedAuthorizations.values());
        
        //Collection<OAuth2Authorization> values = this.initializedAuthorizations.values();
        //for (OAuth2Authorization authorization : values) {
        //    if (hasToken(authorization, token, tokenType)) {
        //        log.debug("findByToken.exit; returning initialized: {}", authorization);
        //        return authorization;
        //    }
        //}
        log.info("findByToken.exit; no authorization found for token: {}, type: {}; authorizations size: {}, codes size: {}", 
                token, tkType, authorizations.estimatedSize(), codes.size());
        return null;
    }

    @Override
    public void onRemoval(@org.checkerframework.checker.nullness.qual.Nullable String key,
            @org.checkerframework.checker.nullness.qual.Nullable OAuth2Authorization value, RemovalCause cause) {
        boolean removed = false;
        log.debug("onRemoval.enter; got key: {}, authorization: {}, cause: {}", key, value, cause);
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = value.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            removed = codes.remove(authorizationCode.getToken().getTokenValue()) != null;
        }
        log.debug("onRemoval.exit; removed: {}", removed);
    }
/*    
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
*/
}
