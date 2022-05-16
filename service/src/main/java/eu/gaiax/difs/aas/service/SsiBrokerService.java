package eu.gaiax.difs.aas.service;

import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_SCOPE;
import static eu.gaiax.difs.aas.model.TrustServicePolicy.GET_LOGIN_PROOF_INVITATION;
import static eu.gaiax.difs.aas.model.TrustServicePolicy.GET_LOGIN_PROOF_RESULT;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
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

@Service
public class SsiBrokerService extends SsiClaimsService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    @Value("${aas.id-token.clock-skew}")
    private Duration clockSkew;

    @Value("${aas.id-token.issuer}")
    private String idTokenIssuer;

    private final ScopeProperties scopeProperties;
    private final ServerProperties serverProperties;

    private final Map<String, Map<String, Object>> authCache = new ConcurrentHashMap<>();
    
    public SsiBrokerService(TrustServiceClient trustServiceClient, ScopeProperties scopeProperties, ServerProperties serverProperties) {
        super(trustServiceClient);
        this.scopeProperties = scopeProperties;
        this.serverProperties = serverProperties;
    }

    public Model oidcAuthorize(Model model) {
        log.debug("oidcAuthorize.enter; got model: {}", model);

        Map<String, Object> params = new HashMap<>();
        params.put("namespace", "Login");

        Set<String> scopes = processScopes(model);
        params.put("scope", scopes);

        // they can be provided in re-login scenario..
        processAttribute(model, params, "sub");
        processAttribute(model, params, "max_age");

        Map<String, Object> result = trustServiceClient.evaluate(GET_LOGIN_PROOF_INVITATION, params);
        String link = (String) result.get("link");
        String requestId = (String) result.get("requestId");
        Map<String, Object> data = initAuthRequest(requestId.toString(), scopes, "OIDC");
        log.debug("oidcAuthorize; OIDC request {} stored: {}", requestId, data);

        // encode link otherwise it'll not pass security check
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        model.addAttribute("loginType", "OIDC");

        log.debug("oidcAuthorize.exit; returning model: {}", model);
        return model;
    }

    public Model siopAuthorize(Model model) {
        log.debug("siopAuthorize.enter; got model: {}", model);

        Set<String> scopes = processScopes(model);

        UUID requestId = UUID.randomUUID();
        String link = buildRequestString(scopes, requestId);
        initAuthRequest(requestId.toString(), scopes, "SIOP");
        
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        model.addAttribute("loginType", "SIOP");

        log.debug("siopAuthorize.exit; returning model: {}", model);
        return model;
    }

    private Set<String> processScopes(Model model) {
        Set<String> scopes = new HashSet<>();
        //scopes.add("openid");
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
            Set<String> requestedScopes = (Set<String>) authCache.get(requestId).get("scope");
            Set<String> requestedClaims = scopeProperties.getScopes().entrySet().stream()
                    .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
            // special handling for auth_time..
            requestedClaims.remove("auth_time");
            
            DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder()
                .issuer(idTokenIssuer)
                .audience(serverProperties.getBaseUrl())
                .build(), requestedClaims);
            try {
                verifier.verify(JWTClaimsSet.parse(response), null);
            } catch(ParseException | BadJWTException ex) {
                authCache.remove(requestId);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: " + ex.getMessage()); 
            }
                
            String issuer = (String) response.get("iss");
            String subject = (String) response.get("sub");
            // should be the same..
            if (!issuer.equals(subject)) {
                log.info("processSiopLoginResponse; issuer and subject have different values");
            }
                
            try {
                subject = new String(Base64.getUrlDecoder().decode(subject));
                log.debug("processSiopLoginResponse; subject: {}", subject);
            } catch (Exception ex) {
                log.debug("processSiopLoginResponse; subject is not base64-encoded: {}", subject);
            }
        }
        addAuthData(requestId, response);
        log.debug("processSiopLoginResponse.exit; error processed: {}", error != null);
    }
    
    private Map<String, Object> initAuthRequest(String requestId, Set<String> scopes, String authType) {
        Map<String, Object> data = new HashMap<>();
        data.put("request_time", LocalDateTime.now());
        data.put("scope", scopes);
        data.put("auth_type", authType);
        Map<String, Object> existing = authCache.put(requestId, data);
        if (existing != null) {
            log.warn("addAuthRequest; data for request {} alreday stored: {}", requestId, existing);
        }
        return data;
    }
    
    public boolean setAdditionalParameters(String requestId, Map<String, Object> additionalParams) {
        log.debug("setAdditionalParameters.enter; got request: {} params: {}", requestId, additionalParams);
        boolean result = true;
        Map<String, Object> request = authCache.get(requestId);
        if (request == null) {
            // throw error?
            result = false;
        } else {
            request.put("additional_parameters", additionalParams);
            authCache.put(requestId, request);
        }
        log.debug("addAuthData.exit; updated: {}", result);
        return result;
        
    }
    
    private boolean addAuthData(String requestId, Map<String, Object> data) {
        log.debug("addAuthData.enter; got request: {} claims size: {}", requestId, data.size());
        boolean result = true;
        Map<String, Object> request = authCache.get(requestId);
        if (request == null) {
            // throw error?
            result = false;
        } else {
            data.putAll(request);
        }
        authCache.put(requestId, data);
        log.debug("addAuthData.exit; returning: {}, stored claims: {}", result, data.size());
        return result;
    }

    private boolean isValidRequest(String requestId) {
        Map<String, Object> request = authCache.get(requestId);
        return request != null && //(request.get("sub") != null || request.get("error") != null) &&
                ((LocalDateTime) request.get("request_time")).isAfter(LocalDateTime.now().minus(clockSkew));
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

    public Map<String, Object> getUserClaims(String requestId, boolean required, Collection<String> requestedClaims) {
        Map<String, Object> userClaims = getUserClaims(requestId, required);
        if (userClaims == null) {
            return null;
        }
        
        return userClaims.entrySet().stream()
                .filter(e -> e.getValue() != null && requestedClaims.contains(e.getKey())).collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
    }
    
    public Map<String, Object> getUserClaims(String requestId, boolean required, Collection<String> requestedScopes, Collection<String> requestedClaims) {
        Map<String, Object> userClaims = getUserClaims(requestId, required);
        if (userClaims == null) {
            return null;
        }
        
        // return claims which corresponds to requested scopes only..
        Set<String> scopedClaims = scopeProperties.getScopes().entrySet().stream()
                .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
        return userClaims.entrySet().stream()
                .filter(e -> e.getValue() != null && (scopedClaims.contains(e.getKey()) || requestedClaims.contains(e.getKey())))
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
    }
    
    public Map<String, Object> getUserClaims(String requestId, boolean required) {
        Map<String, Object> userClaims = authCache.get(requestId); 
        if (userClaims == null) {
            log.warn("getUserClaims; no claims found for request: {}, required: {}", requestId, required);
            if (required) {
                userClaims = loadTrustedClaims(GET_LOGIN_PROOF_RESULT, requestId);
                addAuthData(requestId, userClaims);
            }
        } else if (!userClaims.containsKey("sub") && !userClaims.containsKey("error")) {
            if (required) {
                userClaims = loadTrustedClaims(GET_LOGIN_PROOF_RESULT, requestId);
                addAuthData(requestId, userClaims);
            } else {
                userClaims = null;
            }
        }
        return userClaims;
    }

    public Set<String> getUserScopes(String requestId) {
        Map<String, Object> userClaims = authCache.get(requestId);
        if (userClaims == null) {
            log.warn("getUserScopes; no claims found for request: {}", requestId);
            throw new OAuth2AuthenticationException(INVALID_REQUEST);
        }
        
        Set<String> scopes = (Set<String>) userClaims.get("scope");
        if (scopes == null) {
            log.warn("getUserScopes; no scopes found for request: {}", requestId);
            throw new OAuth2AuthenticationException(INVALID_SCOPE);
        }

        //Map<String, String> claims = scopeProperties.getScopes().entrySet().stream().map(e -> e.getValue())
        return scopes; //userClaims.keySet().stream().filter(c -> scopeProperties.getScopes().entrySet() .values().contains(c)).collect(Collectors.toSet());
    }
    
    public Map<String, Object> getAdditionalParameters(String requestId) {
        Map<String, Object> userClaims = authCache.get(requestId);
        if (userClaims == null) {
            // log it..
            return null;
        }
        Map<String, Object> params = (Map<String, Object>) userClaims.get("additional_parameters");
        if (params == null) {
            return null;
        }
        return new HashMap<>(params);
    }
    
}
