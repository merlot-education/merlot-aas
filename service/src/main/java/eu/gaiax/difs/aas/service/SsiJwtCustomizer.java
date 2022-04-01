package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class SsiJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log = LoggerFactory.getLogger(SsiJwtCustomizer.class);

    @Autowired
    private  SsiUserService ssiUserService;

    @Override
    public void customize(JwtEncodingContext context) {
        log.debug("customize.enter; got context: {}", context);

        if ("id_token".equals(context.getTokenType().getValue())) {
            Map<String, Object> userDetails = ssiUserService.getUserClaims();
            context.getClaims().claims(claims -> claims.putAll(userDetails));
        }

        log.debug("customize.exit;");
    }

}
