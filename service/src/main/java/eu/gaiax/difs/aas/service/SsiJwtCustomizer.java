package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class SsiJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log = LoggerFactory.getLogger(SsiJwtCustomizer.class);

    @Autowired
    private  SsiUserService ssiUserService;

    @Override
    public void customize(JwtEncodingContext context) {
        log.debug("customize.enter; got context: {}", context);
        String requestId = getRequestId(context);
        
        if ("id_token".equals(context.getTokenType().getValue())) {
            Map<String, Object> userDetails = ssiUserService.getUserClaims(requestId, false);
            //userDetails.co
            //context.getClaims().
            context.getClaims().claims(claims -> {
                Object iat = claims.get("iat"); //issued_at?
                Object authTime = iat == null ? Instant.now() : iat;
                claims.putAll(userDetails);
                claims.putIfAbsent("auth_time", authTime);
            });
        }
        log.debug("customize.exit; got subject: {}", requestId);
    }

    private String getRequestId(JwtEncodingContext context) {
        AtomicReference<String> requestId = new AtomicReference<>();
        context.getClaims().claims(claims -> requestId.set((String) claims.get("sub")));
        return requestId.get();
    }

}
