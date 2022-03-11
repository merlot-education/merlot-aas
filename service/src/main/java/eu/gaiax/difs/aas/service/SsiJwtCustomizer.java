package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

public class SsiJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    
    private static final Logger log = LoggerFactory.getLogger(SsiJwtCustomizer.class);

    @Override
    public void customize(JwtEncodingContext context) {
        log.debug("customize.enter; got context: {}", context);
        String[] sub = new String[] {null};
        context.getClaims().claims(cc -> {
            sub[0] = (String) cc.get("sub"); 
            cc.put("email", sub[0] + "@oidc.ssi");
            cc.put("name", sub[0]);
        });
        // TODO: get claims from UserDetailService for requestId (sub[0])
        // then customize context with found claims
        log.debug("customize.exit; got subject: {}", sub[0]);
    }

}
