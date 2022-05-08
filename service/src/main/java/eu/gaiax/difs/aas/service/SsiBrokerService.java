package eu.gaiax.difs.aas.service;

import static java.time.temporal.ChronoUnit.MILLIS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import eu.gaiax.difs.aas.properties.ScopeProperties;
import eu.gaiax.difs.aas.properties.ServerProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.server.ResponseStatusException;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SsiBrokerService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    @Value("${aas.id-token.clock-skew}")
    private Duration clockSkew;

    @Value("${aas.id-token.issuer}")
    private String idTokenIssuer;

    @Value("${aas.tsa.delay}")
    private long millisecondsToDelay;

    @Value("${aas.tsa.duration}")
    private long requestingDuration;

    
    private final TrustServiceClient trustServiceClient;
    
    private final ScopeProperties scopeProperties;
    private final ServerProperties serverProperties;

    private final Map<String, Map<String, Object>> siopRequestCache = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> userClaimsCache = new ConcurrentHashMap<>();

    public Model oidcAuthorize(Model model) {
        log.debug("authorize.enter; got model: {}", model);

        Map<String, Object> params = new HashMap<>();
        params.put("namespace", "Login");

        Set<String> scopes = processScopes(model);
        params.put("scope", scopes);

        // they can be provided in re-login scenario..
        processAttribute(model, params, "sub");
        processAttribute(model, params, "max_age");

        Map<String, Object> result = trustServiceClient.evaluate("GetLoginProofInvitation", params);
        String link = (String) result.get("link");
        String requestId = (String) result.get("requestId");

        // encode link otherwise it'll not pass security check
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        model.addAttribute("loginType", "OIDC");

        log.debug("authorize.exit; returning model: {}", model);
        return model;
    }

    public Model siopAuthorize(Model model) {
        log.debug("siopAuthorize.enter; got model: {}", model);

        Set<String> scopes = processScopes(model);

        UUID requestId = UUID.randomUUID();
        String link = buildRequestString(scopes, requestId);
        cacheSiopData(requestId.toString(), scopes);
        
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        model.addAttribute("loginType", "SIOP");

        log.debug("siopAuthorize.exit; returning model: {}", model);
        return model;
    }

    private Set<String> processScopes(Model model) {
        Set<String> scopes = new HashSet<>();
        scopes.add("openid");
        Object o = model.getAttribute("scope");
        if (o != null) {
            Arrays.stream((String[]) o).forEach(s -> scopes.addAll(Arrays.asList(s.split(" "))));
        }
        return scopes;
    }

    private void processAttribute(Model model, Map<String, Object> params, String attribute) {
        Object o = model.getAttribute(attribute);
        if (o != null) {
            params.put(attribute, o);
        }
    }

    private String buildRequestString(Set<String> scopes, UUID requestId) {
        List<String> params = new ArrayList<>();
        params.add("scope=" + String.join(" ", scopes));
        params.add("response_type=id_token");
        params.add("client_id=" + serverProperties.getBaseUrl());
        params.add("redirect_uri=" + serverProperties.getBaseUrl() + "/ssi/siop-callback");
        params.add("response_mode=post");
        params.add("nonce=" + requestId);
        return "openid://?" + String.join("&", params);
    }

    public byte[] getQR(String elink) {
        // the incoming link is encoded, we must decode it first
        log.debug("getQR.enter; got elink: {}", elink);
        String link = new String(Base64.getUrlDecoder().decode(elink));
        QRCodeWriter barcodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = null;
        try {
            bitMatrix = barcodeWriter.encode(link, BarcodeFormat.QR_CODE, 200, 200);
        } catch (WriterException e) {
            log.error("getQR.error; QR data generation failed", e);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ImageIO.write(MatrixToImageWriter.toBufferedImage(bitMatrix), "png", baos);
        } catch (IOException e) {
            log.error("getQR.error; Failed to generate image from QR data", e);
        }
        log.debug("getQR.exit; returning image for link: {}", link);
        return baos.toByteArray();
    }

    public void processSiopLoginResponse(Map<String, Object> response) {
        log.debug("processSiopLoginResponse.enter; got response: {}", response);
        String requestId = (String) response.get("nonce");
        if (requestId == null || !isValidRequest(requestId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: invalid nonce"); 
        } 
        
        String error = (String) response.get("error");
        if (error == null) {
            Set<String> requestedScopes = (Set<String>) siopRequestCache.get(requestId).get("scope");
            Set<String> requestedClaims = scopeProperties.getScopes().entrySet().stream()
                    .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
            
            DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder()
                .issuer(idTokenIssuer)
                .audience(serverProperties.getBaseUrl())
                .build(), requestedClaims);
            try {
                verifier.verify(JWTClaimsSet.parse(response), null);
            } catch(ParseException | BadJWTException ex) {
                siopRequestCache.remove(requestId);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: " + ex.getMessage()); 
            }
                
            String issuer = (String) response.get("iss");
            String subject = (String) response.get("sub");
            // should be the same..
            if (!issuer.equals(subject)) {
                log.warn("processSiopLoginResponse; issuer and subject have different values");
            }
                
            try {
                subject = new String(Base64.getUrlDecoder().decode(subject));
                log.debug("processSiopLoginResponse; subject: {}", subject);
            } catch (Exception ex) {
                log.debug("processSiopLoginResponse; subject is not base64-encoded: {}", subject);
            }
        }
        siopRequestCache.remove(requestId);
        userClaimsCache.put(requestId, response);
        //log.debug("processSiopLoginResponse.exit; returning: {}", result);
    }
    
    private void cacheSiopData(String requestId, Set<String> scopes) {
        if (!siopRequestCache.containsKey(requestId)) {
            Map<String, Object> data = new HashMap<>();
            data.put("request_time", LocalDateTime.now());
            data.put("scope", scopes);
            siopRequestCache.put(requestId, data);
        } else {
            throw new OAuth2AuthenticationException("loginFailed");
        }
    }

    private boolean isValidRequest(String requestId) {
        Map<String, Object> request = siopRequestCache.get(requestId);
        return request != null && ((LocalDateTime) request.get("request_time")).isAfter(LocalDateTime.now().minus(clockSkew));
    }
    
    public Map<String, Object> getSubjectClaims(String subjectId, boolean required, Map<String, Object> params) {
        log.debug("getSubjectClaims.enter; got subject: {}, required: {}", subjectId, required);
        Map<String, Object> claims = getUserClaims(subjectId, required);
        if (required) {
            // claims override params
            if (claims != null) {
                params.putAll(claims);
            }
            claims = params;
        } else {
            // params override claims
            if (claims == null) {
                claims = params;
            } else {
                claims.putAll(params);
            }
        }
        log.debug("getSubjectClaims.exit; returning: {}", claims == null ? null : claims.size());
        return claims;
    }

    public Map<String, Object> getUserClaims(String requestId, boolean required, Collection<String> requestedScopes) {
        Map<String, Object> userClaims = getUserClaims(requestId, required);
        if (userClaims == null) {
            return null;
        }
        
        // return claims which corresponds to requested scopes only..
        Set<String> requestedClaims = scopeProperties.getScopes().entrySet().stream()
                .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
        return userClaims.entrySet().stream()
                .filter(e -> e.getValue() != null && requestedClaims.contains(e.getKey())).collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
    }
    
    public Map<String, Object> getUserClaims(String requestId, boolean required) {
        Map<String, Object> userClaims = userClaimsCache.get(requestId); 
        if (userClaims == null && required) {
            userClaims = loadUserClaims(requestId);
        }
        return userClaims;
    }
    
    private Map<String, Object> loadUserClaims(String requestId) {
        LocalTime requestingStart = LocalTime.now();
        LocalTime durationRestriction = requestingStart.plusNanos(1_000_000 * requestingDuration);

        while (LocalTime.now().isBefore(durationRestriction)) {
            Map<String, Object> evaluation = trustServiceClient.evaluate("GetLoginProofResult", Collections.singletonMap("requestId", requestId));

            if (evaluation.get("status") == null || !(evaluation.get("status") instanceof AccessRequestStatusDto)) {
                log.error("Exception during call Evaluate of TrustServiceClient, response status is not specified: {}", evaluation.get("status"));
                throw new OAuth2AuthenticationException("loginFailed");
            }

            switch ((AccessRequestStatusDto) evaluation.get("status")) {
                case ACCEPTED:
                    userClaimsCache.put(requestId, evaluation);
                    return evaluation;
                case PENDING:
                    delayNextRequest();
                    break;
                case REJECTED:
                    throw new OAuth2AuthenticationException("loginRejected");
                case TIMED_OUT:
                    log.error("Exception during call Evaluate of TrustServiceClient, response status: {}", evaluation.get("status"));
                    throw new OAuth2AuthenticationException("loginTimeout");
            }
        }

        log.error("Time for calling TrustServiceClient expired, time spent: {} ms", requestingStart.until(LocalTime.now(), MILLIS));
        throw new OAuth2AuthenticationException("loginTimeout");
    }

    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(millisecondsToDelay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
    
}
