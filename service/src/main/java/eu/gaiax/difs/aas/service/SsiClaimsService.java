package eu.gaiax.difs.aas.service;

import static eu.gaiax.difs.aas.model.SsiAuthErrorCodes.*;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import eu.gaiax.difs.aas.cache.DataCache;
import eu.gaiax.difs.aas.cache.caffeine.CaffeineDataCache;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class SsiClaimsService {
    
    @Value("${aas.cache.size}")
    private int cacheSize;
    @Value("${aas.cache.ttl}")
    private Duration ttl;
    @Value("${aas.tsa.delay}")
    private long delay;
    @Value("${aas.tsa.duration}")
    private long duration;
    
    protected final TrustServiceClient trustServiceClient;
    
    protected DataCache<String, Map<String, Object>> claimsCache;
    
    public SsiClaimsService(TrustServiceClient trustServiceClient) {
        this.trustServiceClient = trustServiceClient;
    }
    
    @PostConstruct
    public void init() {
    	log.info("init; cacheSize: {}, ttl: {}", cacheSize, ttl);
        claimsCache = new CaffeineDataCache<>(1024, ttl, null); 
    }
    
    protected Map<String, Object> getTrustedClaims(String policy, String requestId) {
        Map<String, Object> evaluation = trustServiceClient.evaluate(policy, Map.of(TrustServiceClient.PN_REQUEST_ID, requestId));

        Object o = evaluation.get(TrustServiceClient.PN_STATUS);
        if (o == null || !(o instanceof AccessRequestStatusDto)) {
            //log.error("loadTrustedClaims; unknown response status: {}", o);
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
        return evaluation;
    }

    protected Map<String, Object> loadTrustedClaims(String policy, String requestId) {
        Instant finish = Instant.now().plusNanos(1_000_000 * duration);
        while (Instant.now().isBefore(finish)) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(policy, Map.of(TrustServiceClient.PN_REQUEST_ID, requestId));

            Object o = evaluation.get(TrustServiceClient.PN_STATUS);
            if (o == null || !(o instanceof AccessRequestStatusDto)) {
                //log.error("loadTrustedClaims; unknown response status: {}", o);
                throw new OAuth2AuthenticationException(SERVER_ERROR);
            }

            switch ((AccessRequestStatusDto) o) {
                case ACCEPTED:
                    return evaluation;
                case PENDING:
                	delayNextRequest();
                	break;
                case REJECTED:
                    throw new OAuth2AuthenticationException(LOGIN_REJECTED);
                case TIMED_OUT:
                    throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
            }
        }
        throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
    }
    
    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
    

}
