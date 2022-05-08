package eu.gaiax.difs.aas.controller;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.REJECTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.TIMED_OUT;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.imageio.ImageIO;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

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
import eu.gaiax.difs.aas.client.config.JwkConfig;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.properties.ServerProperties;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@Import(JwkConfig.class)
public class AuthenticationFlowTest {

    @Value("${aas.iam.base-uri}")
    private String keycloakUri;
    
    //@Autowired
    //private JwtDecoder jwtDecoder;
    
    @Autowired
    private ServerProperties serverProps;
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private TrustServiceClient trustServiceClient;

    @Test
    void testOidcLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig("GetLoginProofResult", ACCEPTED);

        Map<String, Object> claims = getOidcClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
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
        // TODO: call to /userinfo doesn't work because of auth issue on /jwks endpoint
        // but it works from oidc auth flow, and we do provide /userinfo endpoint
        // so, will investigate it later..
        
        //String accessToken = (String) claims.get("access_token");
        //Jwt jwt = jwtDecoder.decode(accessToken);
        //assertNotNull(jwt);
        
        //MvcResult result = mockMvc.perform(
        //        get("/userinfo")
        //        .header("Authorization", "Bearer " + accessToken)
        //        .accept(MediaType.APPLICATION_JSON))
        //    .andExpect(status().isOk())
        ////    .andDo(print())
        //    .andReturn();
    }

    @Test
    void testOidcLoginMaxScope() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig("GetLoginProofResult", ACCEPTED);

        Map<String, Object> claims = getOidcClaims("openid profile email", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "OIDC", "secret", Map.of("max_age", 1), s -> "uri://" + s, null);

        // check claims..
        assertNotNull(claims.get("iss"));
        assertNotNull(claims.get("sub"));
        assertNotNull(claims.get("auth_time"));
        assertNotNull(claims.get("name"));
        assertNotNull(claims.get("given_name"));
        assertNotNull(claims.get("family_name"));
        //assertNotNull(claims.get("middle_name"));
        assertNotNull(claims.get("preferred_username"));
        assertNotNull(claims.get("gender"));
        assertNotNull(claims.get("birthdate"));
        assertNotNull(claims.get("updated_at"));
        assertNotNull(claims.get("email"));
        assertNotNull(claims.get("email_verified"));
    }
    
    @Test
    void testSiopLoginFlow() throws Exception {
        Map<String, Object> claims = getOidcClaims("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + serverProps.getBaseUrl() + "&redirect_uri=" + serverProps.getBaseUrl() + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, rid -> {
                        try {
                            String rq = "id_token={\"iss\": \"https://self-issued.me/v2\", \"sub\": \"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\", " + 
                                    "\"aud\": \"" + serverProps.getBaseUrl() + "\", \"nonce\": \"" + rid + "\", \"exp\": " + new Date().getTime() + 
                                    ", \"iat\": 1311280970, \"auth_time\": \"" + new Date().getTime() + "\"}";
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

    private Map<String, Object> getOidcClaims(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol, 
            String secret, Map<String, Object> optional, Function<String, String> urlBuilder, Consumer<String> callback) throws Exception {

        String authCode = getOidcAuth(scope, state, responseType, clientId, redirectUri, nonce, protocol, optional, urlBuilder, callback);
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
    
    private String getOidcAuth(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol,
            Map<String, Object> optional, Function<String, String> urlBuilder, Consumer<String> callback) throws Exception {

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("scope", scope);
        params.put("state", state);
        params.put("response_type", responseType);
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("nonce", nonce);
        if (optional != null) {
            params.putAll(optional);
        }

        int idx = 0;
        StringBuilder sb = new StringBuilder();
        for (String key : params.keySet()) {
            if (idx > 0) {
                sb.append("&");
            }
            sb.append(key).append("={").append(key).append("}");
            idx++;
        }
        Object[] values = params.values().toArray(new Object[params.size()]);

        MvcResult result = mockMvc
                .perform(get("/oauth2/authorize?" + sb.toString(), values).accept(MediaType.TEXT_HTML,
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
                .andExpect(header().string("Location", containsString("/oauth2/authorize")))
                .andReturn();
        session = result.getRequest().getSession(false);

        result = mockMvc
                .perform(get("/oauth2/authorize?" + sb.toString(), values)
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(redirectUri))) 
                .andReturn();

        String reUrl = result.getResponse().getRedirectedUrl();
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(reUrl).build().getQueryParams();
        return queryParams.getFirst("code"); // responseType);
    }
/*
    @Test
    void testSiopLoginFlow() throws Exception {

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();

        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/ssi/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();

        session = result.getRequest().getSession(false);
        String requestId = result.getModelAndView().getModel().get("requestId").toString();
        String qrUrl = result.getModelAndView().getModel().get("qrUrl").toString();

        result = mockMvc.perform(
                        get(qrUrl)
                                .accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        String expectedUrl = "openid://" +
                "?scope=openid" +
                "&response_type=id_token" +
                "&client_id=" + serverProps.getBaseUrl() + 
                "&redirect_uri=" + serverProps.getBaseUrl() + "/ssi/siop-callback" +
                "&response_mode=post" +
                "&nonce=" + requestId;
        
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());
        assertEquals(expectedUrl, resultQrUrl);

        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", requestId)
                                .param("password", "SIOP"))
                // as callback was not invoked yet, then it must return error response and redirected back to login page 
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();

        result = mockMvc.perform(
                        post("/ssi/siop-callback")
                                .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                .content("id_token={ \"iss\": \"https://self-issued.me/v2\", " +
                                        "\"sub\": \"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\", " +
                                        "\"aud\": \"" + serverProps.getBaseUrl() + "\", " +
                                        "\"nonce\": \"" + requestId + "\", " +
                                        "\"auth_time\": " + new Date().getTime() + ", " +
                                        "\"exp\": " + new Date().getTime() + ", " +
                                        "\"iat\": 1311280970}"))
                .andExpect(status().isOk())
                .andReturn();
        
        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", requestId)
                                .param("password", "SIOP"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/authorize")))
                .andReturn();

        session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/gaia-x/broker/ssi-siop/endpoint")))
                .andReturn();

        String reUrl = result.getResponse().getRedirectedUrl();
        MultiValueMap<String, String> params = UriComponentsBuilder.fromUriString(reUrl).build().getQueryParams();
        String code = params.getFirst("code");

        result = mockMvc.perform(
                        post("/oauth2/token")
                                .header("Authorization", "Basic YWFzLWFwcC1zaW9wOnNlY3JldDI=")
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .param(OAuth2ParameterNames.CODE, code)
                                .param(OAuth2ParameterNames.GRANT_TYPE, "authorization_code")
                                .param(OAuth2ParameterNames.REDIRECT_URI, keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint"))
                .andExpect(status().isOk())
                .andReturn();

        String jwtStr = result.getResponse().getContentAsString();
        Map<String, Object> jwt = new JacksonJsonParser().parseMap(jwtStr);

        assertNotNull(jwt.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertNotNull(jwt.get(OidcParameterNames.ID_TOKEN));
        assertNotNull(jwt.get(OAuth2ParameterNames.EXPIRES_IN));
        assertNotNull(jwt.get(OAuth2ParameterNames.TOKEN_TYPE));
        assertTrue(((Integer) jwt.get(OAuth2ParameterNames.EXPIRES_IN)) > 500); // default is 300, we set it to 600
        assertEquals("Bearer", jwt.get(OAuth2ParameterNames.TOKEN_TYPE));
    }
*/
    private String decodeQR(byte[] content) throws IOException, ChecksumException, NotFoundException, FormatException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        return new QRCodeReader().decode(bitmap).getText();
    }

    @Test
    void siopCallback_missingParameter() throws Exception {
        mockMvc.perform(
                        post("/ssi/siop-callback").contentType(APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(status().reason(containsString("no id_token nor error provided")));
    }

    @Test
    void siopCallback_errorResponse() throws Exception {
            MvcResult result = mockMvc.perform(
                    get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                            "openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                            keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A")
                            .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/ssi/login")))
            .andReturn();
        
        HttpSession session = result.getRequest().getSession(false);
        
        result = mockMvc.perform(
                    get("/ssi/login")
                            .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                            .cookie(new Cookie("JSESSIONID", session.getId()))
                            .session((MockHttpSession) session))
            .andExpect(status().isOk())
            .andReturn();
        
        session = result.getRequest().getSession(false);
        String requestId = result.getModelAndView().getModel().get("requestId").toString();
        
        result = mockMvc.perform(
                    post("/login")
                            .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .cookie(new Cookie("JSESSIONID", session.getId()))
                            .session((MockHttpSession) session)
                            .param("username", requestId)
                            .param("password", "SIOP"))
            // as callback was not invoked yet, then it must return error response and redirected back to login page 
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/ssi/login")))
            .andReturn();
        
        result = mockMvc.perform(
                        post("/ssi/siop-callback")
                                .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                .content("error=invalid_request&error_description=Unsupported%20response_type%20value&state=" + requestId))
                // we had error response above, so we're redirected back to login page to see errors 
                .andExpect(status().isOk())
                .andReturn();
        
        result = mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content("id_token={ \"iss\": \"https://self-issued.me/v2\", " +
                                    "\"sub\": \"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\", " +
                                    "\"aud\": \"" + serverProps.getBaseUrl() + "/ssi/siop-callback\", " +
                                    "\"nonce\": \"" + requestId + "\", " +
                                    "\"exp\": " + new Date().getTime() + ", " +
                                    "\"iat\": 1311280970}"))
            .andExpect(status().isBadRequest()) // no requestId any more
            .andExpect(status().reason(containsString("invalid nonce")))
            .andReturn();
        
        result = mockMvc.perform(
                    post("/login")
                            .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .cookie(new Cookie("JSESSIONID", session.getId()))
                            .session((MockHttpSession) session)
                            .param("username", requestId)
                            .param("password", "SIOP"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/ssi/login")))
            .andReturn();
    }

    
    @Test
    void testLoginFlowTimeout() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig("GetLoginProofResult", TIMED_OUT);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/ssi/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();
        session = result.getRequest().getSession(false);

        String qrUrl = (String) result.getModelAndView().getModel().get("qrUrl");
        mockMvc.perform(
                        get(qrUrl)
                                .accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk());

        String userId = (String) result.getModelAndView().getModel().get("requestId");
        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", userId)
                                .param("password", "OIDC"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        session = result.getRequest().getSession(false);

        assertEquals("loginTimeout", session.getAttribute("AUTH_ERROR"));
    }

    @Test
    void testLoginFlowReject() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig("GetLoginProofResult", REJECTED);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/ssi/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();
        session = result.getRequest().getSession(false);

        String qrUrl = (String) result.getModelAndView().getModel().get("qrUrl");
        mockMvc.perform(
                        get(qrUrl)
                                .accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk());

        String userId = (String) result.getModelAndView().getModel().get("requestId");
        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", userId)
                                .param("password", "OIDC"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        session = result.getRequest().getSession(false);

        assertEquals("loginRejected", session.getAttribute("AUTH_ERROR"));
    }

}
