package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class SsiJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log = LoggerFactory.getLogger(SsiJwtCustomizer.class);

    @Autowired
    private  SsiBrokerService ssiBrokerService;

    @Override
    public void customize(JwtEncodingContext context) {
        log.debug("customize.enter; got context: {}", context);
        String requestId = getRequestId(context);
        
        boolean updated = false;
        if ("id_token".equals(context.getTokenType().getValue())) {
            OAuth2Authorization auth = context.get(OAuth2Authorization.class);
            OAuth2AuthorizationRequest oar = auth.getAttribute(OAuth2AuthorizationRequest.class.getName());
            Map<String, Object> additionalParams = oar.getAdditionalParameters();
            if (additionalParams != null && !additionalParams.isEmpty()) {
                updated = ssiBrokerService.setAdditionalParameters(requestId, additionalParams);
            }
            // the below is required in case when additional claims were requested in id_token only.
            // but this parameter (request) is not supported by Spring Boot yet
            //Map<String, Object> userDetails = ssiBrokerService.getUserClaims(requestId, false, oar.getScopes()); // required?
            //boolean needAuthTime = oar.getAdditionalParameters().get("max_age") != null; 
            //if (userDetails != null) {
            //    for (Map.Entry<String, Object> e: userDetails.entrySet()) {
            //        if (needAuthTime || !e.getKey().equals("auth_time")) {
            //            context.getClaims().claim(e.getKey(), e.getValue());
            //        }
            //    }
            //}            
        }
        log.debug("customize.exit; updated claims: {} for request: {}", updated, requestId);
    }

    private String getRequestId(JwtEncodingContext context) {
        AtomicReference<String> requestId = new AtomicReference<>();
        context.getClaims().claims(claims -> requestId.set((String) claims.get("sub")));
        return requestId.get();
    }

}
