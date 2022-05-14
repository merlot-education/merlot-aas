package eu.gaiax.difs.aas.controller;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.REJECTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.TIMED_OUT;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.FormatException;
import com.google.zxing.NotFoundException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.client.TrustServicePolicy;
import eu.gaiax.difs.aas.properties.ServerProperties;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
public class AuthenticationFlowTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    @Value("${aas.iam.base-uri}")
    private String keycloakUri;
    
    @Autowired
    private ServerProperties serverProps;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    protected ObjectMapper mapper;
    @Autowired
    private TrustServiceClient trustServiceClient;

    @Test
    void testOidcLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", "secret", null, s -> "uri://" + s, null);

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNull(claims.get("auth_time"));
        assertNull(claims.get("name"));
        assertNull(claims.get("given_name"));
        assertNull(claims.get("family_name"));
        assertNull(claims.get("middle_name"));
        assertNull(claims.get("preferred_username"));
        assertNull(claims.get("gender"));
        assertNull(claims.get("birthdate"));
        assertNull(claims.get("updated_at"));
        assertNull(claims.get("email"));
        assertNull(claims.get("email_verified"));
/*
        //Map.of("max_age", 1), 
        // now test session evaluation..
        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}" +
                                        "&max_age={age}&id_token_hint={hint}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "1", idToken)
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML) // must re-login??
                        //.session((MockHttpSession) session)
                )
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();

        HttpSession session = result.getRequest().getSession(false);

        mockMvc.perform(
                        get("/ssi/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();
*/
        Map<String, Object> userInfo = getUserInfo((String) claims.get("access_token"));
        assertEquals(claims.get("iss"), userInfo.get("iss"));
        assertEquals(claims.get("sub"), userInfo.get("sub"));
    }

    @Test
    void testOidcLoginMaxScope() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid profile email", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "OIDC", "secret", Map.of("max_age", 1), s -> "uri://" + s, null);

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNotNull(claims.get("auth_time"));
        assertNull(claims.get("name"));
        assertNull(claims.get("given_name"));
        assertNull(claims.get("family_name"));
        //assertNotNull(claims.get("middle_name"));
        assertNull(claims.get("preferred_username"));
        assertNull(claims.get("gender"));
        assertNull(claims.get("birthdate"));
        assertNull(claims.get("updated_at"));
        assertNull(claims.get("email"));
        assertNull(claims.get("email_verified"));

        Map<String, Object> userInfo = getUserInfo((String) claims.get("access_token"));
        assertEquals(claims.get("iss"), userInfo.get("iss"));
        assertEquals(claims.get("sub"), userInfo.get("sub"));
        assertNotNull(userInfo.get("auth_time"));
        assertNotNull(userInfo.get("name"));
        assertNotNull(userInfo.get("given_name"));
        assertNotNull(userInfo.get("family_name"));
        //assertNotNull(userInfo.get("middle_name"));
        assertNotNull(userInfo.get("preferred_username"));
        assertNotNull(userInfo.get("gender"));
        assertNotNull(userInfo.get("birthdate"));
        assertNotNull(userInfo.get("updated_at"));
        assertNotNull(userInfo.get("email"));
        assertNotNull(userInfo.get("email_verified"));
    }
    
    @Test
    void testOidcLoginAdditionalClaims() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "OIDC", "secret", 
                Map.of("claims", "{\"userinfo\": {\"name\": {\"essential\": true}, \"email\": null}, \"id_token\": {\"auth_time\": {\"essential\": true}}}"), 
                s -> "uri://" + s, null);

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNotNull(claims.get("auth_time"));
        assertNull(claims.get("name"));
        assertNull(claims.get("email"));

        Map<String, Object> userInfo = getUserInfo((String) claims.get("access_token"));
        assertEquals(claims.get("iss"), userInfo.get("iss"));
        assertEquals(claims.get("sub"), userInfo.get("sub"));
        assertNull(userInfo.get("auth_time"));
        assertNotNull(userInfo.get("name"));
        assertNotNull(userInfo.get("email"));
    }
    
    @Test
    void testSiopLoginFlow() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + serverProps.getBaseUrl() + "&redirect_uri=" + serverProps.getBaseUrl() + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, rid -> {
                        try {
                            Map<String, Object> params = new HashMap<>();
                            params.put("iss", "https://self-issued.me/v2");
                            params.put("sub", "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put("aud", serverProps.getBaseUrl());
                            params.put("nonce", rid);
                            params.put("exp", Instant.now().plusSeconds(600).getEpochSecond());
                            params.put("iat", Instant.now().getEpochSecond());
                            params.put("auth_time", Instant.now().getEpochSecond());
                            String rq = "id_token=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                );

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNull(claims.get("auth_time"));
        assertNull(claims.get("name"));
        assertNull(claims.get("given_name"));
        assertNull(claims.get("family_name"));
        assertNull(claims.get("middle_name"));
        assertNull(claims.get("preferred_username"));
        assertNull(claims.get("gender"));
        assertNull(claims.get("birthdate"));
        assertNull(claims.get("updated_at"));
        assertNull(claims.get("email"));
        assertNull(claims.get("email_verified"));
    }

    @Test
    void testSiopLoginMaxScope() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid profile email", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", null, rid -> 
                    "openid://?scope=openid profile email&response_type=id_token&client_id=" + serverProps.getBaseUrl() + "&redirect_uri=" + serverProps.getBaseUrl() + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, rid -> {
                        try {
                            long stamp = System.currentTimeMillis();
                            Map<String, Object> params = new HashMap<>();
                            params.put("iss", "https://self-issued.me/v2");
                            params.put("sub", "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put("aud", serverProps.getBaseUrl());
                            params.put("nonce", rid);
                            params.put("exp", Instant.now().plusSeconds(600).getEpochSecond());
                            params.put("iat", Instant.now().getEpochSecond());
                            params.put("auth_time", Instant.now().getEpochSecond());
                            params.put("name", rid);
                            params.put("given_name", rid + ": " + stamp);
                            params.put("family_name", String.valueOf(stamp));
                            params.put("middle_name", "");
                            params.put("preferred_username", rid + " " + stamp);
                            params.put("gender", stamp % 2 == 0 ? "F" : "M");
                            params.put("birthdate", LocalDate.now().minusYears(21).toString());
                            params.put("updated_at", Instant.now().minusSeconds(86400).getEpochSecond());
                            params.put("email", rid + "@oidc.ssi");
                            params.put("email_verified", Boolean.TRUE);
                            String rq = "id_token=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                );

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNull(claims.get("auth_time"));
        assertNull(claims.get("name")); 
        assertNull(claims.get("given_name"));
        assertNull(claims.get("family_name"));
        //assertNull(claims.get("middle_name"));
        assertNull(claims.get("preferred_username"));
        assertNull(claims.get("gender"));
        assertNull(claims.get("birthdate"));
        assertNull(claims.get("updated_at"));
        assertNull(claims.get("email"));
        assertNull(claims.get("email_verified"));

        Map<String, Object> userInfo = getUserInfo((String) claims.get("access_token"));
        //assertEquals(claims.get("iss"), userInfo.get("iss"));
        //assertEquals(claims.get("sub"), userInfo.get("sub"));
        //assertNotNull(userInfo.get("auth_time"));
        assertNotNull(userInfo.get("name"));
        assertNotNull(userInfo.get("given_name"));
        assertNotNull(userInfo.get("family_name"));
        //assertNotNull(userInfo.get("middle_name"));
        assertNotNull(userInfo.get("preferred_username"));
        assertNotNull(userInfo.get("gender"));
        assertNotNull(userInfo.get("birthdate"));
        assertNotNull(userInfo.get("updated_at"));
        assertNotNull(userInfo.get("email"));
        assertNotNull(userInfo.get("email_verified"));
    }

    @Test
    void testOidcLoginTimeout() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, TIMED_OUT);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", null, s -> "uri://" + s, null, "/ssi/login");
        HttpSession session = authResult.getRequest().getSession(false);
        assertEquals("loginTimeout", session.getAttribute("AUTH_ERROR"));
    }

    @Test
    void testOidcLoginReject() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, REJECTED);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", null, s -> "uri://" + s, null, "/ssi/login");
        HttpSession session = authResult.getRequest().getSession(false);
        assertEquals("loginRejected", session.getAttribute("AUTH_ERROR"));
    }

    @Test
    void testOidcLoginErrorRequest() throws Exception {

        Map<String, Object> params = getAuthRequestParams("openid", null, "code", "aas-app-oidc", keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", 
                null, Map.of("request", "error-request"));
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);

        try {
            mockMvc.perform(get("/oauth2/authorize?" + rq, values).accept(MediaType.TEXT_HTML,
                            MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location", containsString("/ssi/login"))).andReturn();
            assertEquals("servlet exception", "got redirect");
        } catch (ServletException ex) {
            // Redirecting to http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint?error=request_not_supported
            assertTrue(ex.getCause() instanceof AccessDeniedException);
        }
    }    
    
    @Test
    void testSiopCallbackError() throws Exception {
        
        MvcResult authResult = getAuthResult("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop", 
                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + serverProps.getBaseUrl() + "&redirect_uri=" + serverProps.getBaseUrl() + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, null, "/ssi/login");
        String requestId = authResult.getRequest().getParameter("username"); 
        HttpSession session = authResult.getRequest().getSession(false);
        
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content("error=invalid_request&error_description=Unsupported%20response_type%20value&nonce=" + requestId))
                // we had error response above, so we're redirected back to login page to see errors 
                .andExpect(status().isOk())
                .andReturn();

        // get /ssi/login and check error presence..
         authResult = mockMvc
                .perform(get("/ssi/login")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        session = authResult.getRequest().getSession(false);
        assertEquals("loginFailed", session.getAttribute("AUTH_ERROR"));
        
        Map<String, Object> params = new HashMap<>();
        params.put("iss", "https://self-issued.me/v2");
        params.put("sub", "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        params.put("aud", serverProps.getBaseUrl());
        params.put("nonce", requestId);
        params.put("exp", Instant.now().plusSeconds(600).getEpochSecond());
        params.put("iat", Instant.now().getEpochSecond());
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content("id_token=" + mapper.writeValueAsString(params)))
            .andExpect(status().isOk()) 
            //.andExpect(status().reason(containsString("invalid nonce"))) // no requestId any more
            .andReturn();
    }
    
    @Test
    void testSiopCallbackMissingParameter() throws Exception {
        mockMvc.perform(
                    post("/ssi/siop-callback").contentType(APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(status().reason(containsString("no id_token nor error provided")));
    }
    
    private Map<String, Object> getAuthClaims(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol, 
            String secret, Map<String, Object> optional, Function<String, String> urlBuilder, Consumer<String> callback) throws Exception {

        String authCode = getAuthCode(scope, state, responseType, clientId, redirectUri, nonce, protocol, optional, urlBuilder, callback);
        String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        MvcResult result = mockMvc.perform(
                post("/oauth2/token")
                        .header("Authorization", "Basic " + bearer)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.CODE, authCode)
                        .param(OAuth2ParameterNames.GRANT_TYPE, "authorization_code")
                        .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri))
                .andExpect(status().isOk())
                .andReturn();

        String token = result.getResponse().getContentAsString();
        Map<String, Object> tokenFields = new JacksonJsonParser().parseMap(token);
        
        assertNotNull(tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertNotNull(tokenFields.get(OidcParameterNames.ID_TOKEN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.EXPIRES_IN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        assertTrue(((Integer) tokenFields.get(OAuth2ParameterNames.EXPIRES_IN)) > 500); // default is 300, we set it to 600
        assertEquals("Bearer", tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        // check session.getMaxInactiveInterval() too?
        
        String accessToken = tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        JWT jwt = JWTParser.parse(accessToken);
        Object o = jwt.getJWTClaimsSet().getClaim("auth_time");
        assertNull(o);
        
        String idToken = tokenFields.get(OidcParameterNames.ID_TOKEN).toString();
        jwt = JWTParser.parse(idToken);
        //o = jwt.getJWTClaimsSet().getClaim("auth_time");
        //assertNotNull(o);
        
        Map<String, Object> claims = new HashMap<>(jwt.getJWTClaimsSet().getClaims());
        claims.put("access_token", accessToken);
        return claims;
    }
    
    private String getAuthCode(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol,
            Map<String, Object> optional, Function<String, String> urlBuilder, Consumer<String> callback) throws Exception {

        MvcResult authResult = getAuthResult(scope, state, responseType, clientId, redirectUri, nonce, protocol, optional, urlBuilder, callback, "/oauth2/authorize");
        HttpSession session = authResult.getRequest().getSession(false);

        Map<String, Object> params = getAuthRequestParams(scope, state, responseType, clientId, redirectUri, nonce, optional);
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);
        
        authResult = mockMvc
                .perform(get("/oauth2/authorize?" + rq, values)
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(redirectUri))) 
                .andReturn();

        String reUrl = authResult.getResponse().getRedirectedUrl();
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(reUrl).build().getQueryParams();
        return queryParams.getFirst("code"); // responseType);
    }

    private MvcResult getAuthResult(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol,
            Map<String, Object> optional, Function<String, String> urlBuilder, Consumer<String> callback, String loginRedirect) throws Exception {

        Map<String, Object> params = getAuthRequestParams(scope, state, responseType, clientId, redirectUri, nonce, optional);
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);

        MvcResult result = mockMvc
                .perform(get("/oauth2/authorize?" + rq, values).accept(MediaType.TEXT_HTML,
                        MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login"))).andReturn();

        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc
                .perform(get("/ssi/login")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        session = result.getRequest().getSession(false);
        String qrUrl = result.getModelAndView().getModel().get("qrUrl").toString();
        String requestId = result.getModelAndView().getModel().get("requestId").toString();

        result = mockMvc
                .perform(get(qrUrl).accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        String expectedUrl = urlBuilder.apply(requestId); 
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());
        assertEquals(expectedUrl, resultQrUrl);

        if (callback != null) {
            callback.accept(requestId);
        }
        
        result = mockMvc
                .perform(post("/login")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session)
                        .param("username", requestId).param("password", protocol))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(loginRedirect))) //!!
                .andReturn();
        return result;
    }
    
    private Map<String, Object> getUserInfo(String accessToken) throws Exception {
        MvcResult result = mockMvc.perform(
                get("/userinfo")
                    .header("Authorization", "Bearer " + accessToken)
                    .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();
        return mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
    }
    
    private Map<String, Object> getAuthRequestParams(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, 
            Map<String, Object> optional) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("scope", scope);
        if (state != null) {
            params.put("state", state);
        }
        params.put("response_type", responseType);
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        if (nonce != null) {
            params.put("nonce", nonce);
        }
        if (optional != null) {
            params.putAll(optional);
        }
        return params;
    }
    
    private String getAuthRequest(Map<String, Object> params) {
        return params.keySet().stream().map(k -> k + "={" + k + "}").collect(Collectors.joining("&"));
    }
    
    private String decodeQR(byte[] content) throws IOException, ChecksumException, NotFoundException, FormatException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        return new QRCodeReader().decode(bitmap).getText();
    }

}
