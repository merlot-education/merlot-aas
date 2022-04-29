package eu.gaiax.difs.aas.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.imageio.ImageIO;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
//import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
//import com.nimbusds.oauth2.sdk.id.ClientID;
//import com.nimbusds.oauth2.sdk.id.Issuer;
//import com.nimbusds.openid.connect.sdk.Nonce;
//import com.nimbusds.openid.connect.sdk.validators.IDTokenClaimsVerifier;
import eu.gaiax.difs.aas.properties.ScopeProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SsiBrokerService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${server.host}")
    private String serverHost;

    @Value("${server.port}")
    private String serverPort;

    @Value("${aas.id-token.ttl}")
    private Long ttl;

    @Value("${aas.id-token.clock-skew}")
    private Integer clockSkew;

    @Value("${aas.id-token.client-id}")
    private String clientId;

    @Value("${aas.id-token.issuer}")
    private String idTokenIssuer;

    private final TrustServiceClient trustServiceClient;
    private final SsiUserService ssiUserService;
    private final ScopeProperties scopeProperties;

    private final Map<String, Map<String, Object>> siopRequestCache = new ConcurrentHashMap<>();

    public String oidcAuthorize(Model model) {
        log.debug("authorize.enter; got model: {}", model);

        Map<String, Object> params = new HashMap<>();
        params.put("namespace", "Login");

        processScopes(model, params);

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
        return "login-template.html";
    }

    public String siopAuthorize(Model model) {
        log.debug("siopAuthorize.enter; got model: {}", model);

        Object o = model.getAttribute("scope");
        if (o == null) {
            throw new OAuth2AuthenticationException("loginFailed");
        }

        UUID requestId = UUID.randomUUID();
        String link = buildRequestString(model, requestId);
        String scope = String.join(" ", ((String[]) o));
        cacheSiopData(requestId.toString(), scope);
        
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        model.addAttribute("loginType", "SIOP");

        log.debug("siopAuthorize.exit; returning model: {}", model);
        return "login-template.html";
    }

    private Set<String> processScopes(Model model, Map<String, Object> params) {
        Set<String> scopes = new HashSet<>();
        scopes.add("openid");
        Object o = model.getAttribute("scope");
        if (o != null) {
            String[] sa = (String[]) o;
            scopes.addAll(Arrays.asList(sa));
        }
        params.put("scope", scopes);
        return scopes;
    }

    private void processAttribute(Model model, Map<String, Object> params, String attribute) {
        Object o = model.getAttribute(attribute);
        if (o != null) {
            params.put(attribute, o);
        }
    }

    private String buildRequestString(Model model, UUID requestId) {
        List<String> params = new ArrayList<>();

        processScopes(model, new HashMap<>()).forEach(scope -> params.add("scope=" + scope));
        params.add("response_type=id_token");
        params.add("client_id=" + issuerUri);
        params.add("redirect_uri=http://" + serverHost + ":" + serverPort + "/ssi/siop-callback");
        params.add("response_mode=post");
        params.add("state=" + requestId);

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

    public String processSiopLoginResponse(Map<String, Object> response) {
        String requestId = (String) response.get("state");
        if (requestId == null || !isValidRequest(requestId)) {
            return "invalid state";
        }

        String error = (String) response.get("error");
        if (error == null) {
            String requiredScope = (String) siopRequestCache.get(requestId).get("scope");
            List<String> claims = scopeProperties.getScopes().get(requiredScope);
        
            DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder()
                .issuer(idTokenIssuer)
                .audience(clientId)
                .build(), new HashSet<String>(claims));
            try {
                verifier.verify(JWTClaimsSet.parse(response), null);
            } catch(ParseException | BadJWTException ex) {
                return ex.getMessage();
            }
        }
        siopRequestCache.remove(requestId);
        ssiUserService.cacheUserClaims(requestId, response);
        return null;
    }

    private void cacheSiopData(String requestId, String scope) {
        if (!siopRequestCache.containsKey(requestId)) {
            Map<String, Object> data = new HashMap<>();
            data.put("request_time", LocalDateTime.now());
            data.put("scope", scope);
            siopRequestCache.put(requestId, data);
        } else {
            throw new OAuth2AuthenticationException("loginFailed");
        }
    }

    private boolean isValidRequest(String requestId) {
        return siopRequestCache.containsKey(requestId) &&
                ((LocalDateTime) siopRequestCache.get(requestId).get("request_time")).isAfter(LocalDateTime.now().minusMinutes(ttl));
    }
}
