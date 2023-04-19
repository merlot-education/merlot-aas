package eu.gaiax.difs.aas.controller;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.REJECTED;
import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.TIMED_OUT;
import static eu.gaiax.difs.aas.client.TrustServiceClient.LINK_SCHEME;

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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
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
import eu.gaiax.difs.aas.model.TrustServicePolicy;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class AuthenticationFlowTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    @Value("${aas.iam.base-uri}")
    private String keycloakUri;
    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;
    @Value("${aas.tsa.request.count}")
    private int tryCount;
    
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private TrustServiceClient trustServiceClient;
    
    private String challenge = UUID.randomUUID().toString(); 
    
    
    private String statusCallback(HttpSession ssn, int finalStatus) {
    	String redirect = null;
    	try {
    		int cnt = 0;
    		do {
    			MvcResult stsResult = mockMvc.perform(get("/ssi/login/status")
    					.contentType(MediaType.APPLICATION_JSON)
    					.cookie(new Cookie("JSESSIONID", ssn.getId())).session((MockHttpSession) ssn))
    				.andReturn();
				cnt++;
				if (cnt <= tryCount) {
					assertEquals(HttpStatus.ACCEPTED.value(), stsResult.getResponse().getStatus());
				} else {
					assertEquals(finalStatus, stsResult.getResponse().getStatus());
					if (finalStatus == 302) {
						redirect = stsResult.getResponse().getRedirectedUrl();
					}
					break;
				}
    		} while (true);
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return redirect;
    }

    @Test
    void testOidcLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null, s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
    }

    @Test
    void testOidcLoginHint() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", "secret", ClientAuthenticationMethod.CLIENT_SECRET_POST,
                null, s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        String token = (String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN);

        Map<String, Object> claims2 = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", "secret", ClientAuthenticationMethod.CLIENT_SECRET_POST, 
                Map.of("max_age", 10, "id_token_hint", token), s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        assertEquals(claims.get(IdTokenClaimNames.SUB), claims2.get(IdTokenClaimNames.SUB));
        Long iat = ((Date) claims.get(IdTokenClaimNames.IAT)).toInstant().getEpochSecond();
        Long authTime = (Long) claims2.get(IdTokenClaimNames.AUTH_TIME);
        assertTrue((authTime - iat) >= 0);
        assertTrue((authTime - iat) < 10);
    }
    
    @Test
    void testOidcLoginMaxScope() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid profile email", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "OIDC", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                Map.of("max_age", 1), s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        assertNotNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(userInfo.get(StandardClaimNames.NAME));
        assertNotNull(userInfo.get(StandardClaimNames.GIVEN_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.FAMILY_NAME));
        assertNull(userInfo.get(StandardClaimNames.MIDDLE_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNotNull(userInfo.get(StandardClaimNames.GENDER));
        assertNotNull(userInfo.get(StandardClaimNames.BIRTHDATE));
        assertNotNull(userInfo.get(StandardClaimNames.UPDATED_AT));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL_VERIFIED));
    }
    
    @Test
    void testOidcLoginAdditionalClaims() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "OIDC", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                Map.of("claims", "{\"userinfo\": {\"name\": {\"essential\": true}, \"email\": null}, \"id_token\": {\"auth_time\": {\"essential\": true}}}"), 
                s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.EMAIL));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        assertNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(userInfo.get(StandardClaimNames.NAME));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL));
    }

    @Test
    void testPkceLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);
        
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(challenge.getBytes(StandardCharsets.US_ASCII));
		String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        Map<String, Object> claims = getAuthClaims("profile openid", "b43e24c9285542418a57b8fc00d283f8", "code", "gxfs-demo",
                "https://demo.gxfs.dev", "sxXudRdJkvAp5kh_QqJQxzij2lDDD4ofb4Fx_rFn7x4", "OIDC", null, ClientAuthenticationMethod.NONE,
                Map.of("code_challenge_method", "S256", "code_challenge", hash), 
                s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
    }
   
    
    @Test
    void testSiopLoginFlow() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", 
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, ssn -> {
                        try {
                            Map<String, Object> params = new HashMap<>();
                            params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
                            params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put(IdTokenClaimNames.AUD, oidcIssuer);
                            params.put(IdTokenClaimNames.NONCE, ssn.getAttribute("requestId"));
                            params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
                            params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
                            params.put(IdTokenClaimNames.AUTH_TIME, Instant.now().getEpochSecond());
                            String rq = OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                );

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));
    }

    @Test
    void testSiopLoginMaxScope() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid profile email", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null, rid -> 
                    "openid://?scope=openid profile email&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, ssn -> {
                        try {
                        	String rid = (String) ssn.getAttribute("requestId");
                            long stamp = System.currentTimeMillis();
                            Map<String, Object> params = new HashMap<>();
                            params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
                            params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put(IdTokenClaimNames.AUD, oidcIssuer);
                            params.put(IdTokenClaimNames.NONCE, rid);
                            params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
                            params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
                            params.put(IdTokenClaimNames.AUTH_TIME, Instant.now().getEpochSecond());
                            params.put(StandardClaimNames.NAME, rid);
                            params.put(StandardClaimNames.GIVEN_NAME, rid + ": " + stamp);
                            params.put(StandardClaimNames.FAMILY_NAME, String.valueOf(stamp));
                            params.put(StandardClaimNames.MIDDLE_NAME, "");
                            params.put(StandardClaimNames.PREFERRED_USERNAME, rid + " " + stamp);
                            params.put(StandardClaimNames.GENDER, stamp % 2 == 0 ? "F" : "M");
                            params.put(StandardClaimNames.BIRTHDATE, LocalDate.now().minusYears(21).toString());
                            params.put(StandardClaimNames.UPDATED_AT, Instant.now().minusSeconds(86400).getEpochSecond());
                            params.put(StandardClaimNames.EMAIL, rid + "@oidc.ssi");
                            params.put(StandardClaimNames.EMAIL_VERIFIED, Boolean.TRUE);
                            String rq = OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                );

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME)); 
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        //assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        //assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        //assertNotNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(userInfo.get(StandardClaimNames.NAME));
        assertNotNull(userInfo.get(StandardClaimNames.GIVEN_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.FAMILY_NAME));
        assertNull(userInfo.get(StandardClaimNames.MIDDLE_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNotNull(userInfo.get(StandardClaimNames.GENDER));
        assertNotNull(userInfo.get(StandardClaimNames.BIRTHDATE));
        assertNotNull(userInfo.get(StandardClaimNames.UPDATED_AT));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL_VERIFIED));
    }

    @Test
    void testOidcLoginTimeout() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, TIMED_OUT);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", null, s -> LINK_SCHEME + s, 
                ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), 
                "/ssi/login?error=login_timed_out");
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME));
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.PASSWORD));
    }

    @Test
    void testOidcLoginReject() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, REJECTED);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "OIDC", null, s -> LINK_SCHEME + s, 
                ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), // .BAD_GATEWAY.value()),
                "/ssi/login?error=login_rejected");
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME));
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.PASSWORD));
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
        
//        Map<String, Object> claims = getAuthClaims("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
//                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", "secret2", null, rid -> 
//                    "openid://?scope=openid&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
//                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, ssn -> {
    	
        MvcResult authResult = getAuthResult("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop", 
                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "SIOP", null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, null, //ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), 
                    "/ssi/login?error=server_error");
        String requestId = authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME); 
        HttpSession session = authResult.getRequest().getSession(false);
        String reUrl = authResult.getResponse().getHeader("Location");
        
        // get /ssi/login and check error presence..
        authResult = mockMvc
                .perform(get(reUrl) 
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        assertEquals(getMessage("server_error", authResult.getRequest().getLocale()), (String) authResult.getModelAndView().getModel().get("errorMessage"));
        
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content("error=invalid_request&error_description=Unsupported%20response_type%20value&nonce=" + requestId))
                // we had error response above, so we're redirected back to login page to see errors 
                .andExpect(status().isOk())
                .andReturn();

        authResult = mockMvc
                .perform(get("/ssi/login?error=invalid_request")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        assertEquals(getMessage("invalid_request", authResult.getRequest().getLocale()), (String) authResult.getModelAndView().getModel().get("errorMessage"));
        
        Map<String, Object> params = new HashMap<>();
        params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
        params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        params.put(IdTokenClaimNames.AUD, oidcIssuer);
        params.put(IdTokenClaimNames.NONCE, requestId);
        params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
        params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content(OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params)))
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
            String secret, ClientAuthenticationMethod authMethod, Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, 
            String> callback) throws Exception {

        String authCode = getAuthCode(scope, state, responseType, clientId, redirectUri, nonce, protocol, optional, urlBuilder, callback);
        MvcResult result;
        if (authMethod == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
            result = mockMvc.perform(
                    post("/oauth2/token")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param(OAuth2ParameterNames.CODE, authCode)
                            .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                            .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                            .param(OAuth2ParameterNames.CLIENT_ID, clientId)
                            .param(OAuth2ParameterNames.CLIENT_SECRET, secret))
                    .andExpect(status().isOk())
                    .andReturn();
        } else if (authMethod == ClientAuthenticationMethod.NONE) { // || secret == null) {
          result = mockMvc.perform(
                post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.CODE, authCode)
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                        .param(OAuth2ParameterNames.CLIENT_ID, clientId)
                        .param("code_verifier", challenge))
                .andExpect(status().isOk())
                .andReturn();
        } else {
          // ClientAuthenticationMethod.CLIENT_SECRET_BASIC
          String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
          result = mockMvc.perform(
                post("/oauth2/token")
                        .header("Authorization", "Basic " + bearer)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.CODE, authCode)
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri))
                .andExpect(status().isOk())
                .andReturn();
        }
        
        String token = result.getResponse().getContentAsString();
        Map<String, Object> tokenFields = new JacksonJsonParser().parseMap(token);
        
        assertNotNull(tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertNotNull(tokenFields.get(OidcParameterNames.ID_TOKEN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.EXPIRES_IN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        assertTrue(((Integer) tokenFields.get(OAuth2ParameterNames.EXPIRES_IN)) > 250); // default is 300, we set it to 600
        assertEquals("Bearer", tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        // check session.getMaxInactiveInterval() too?
        
        String accessToken = tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        JWT jwt = JWTParser.parse(accessToken);
        Object o = jwt.getJWTClaimsSet().getClaim(IdTokenClaimNames.AUTH_TIME);
        assertNull(o);
        
        String idToken = tokenFields.get(OidcParameterNames.ID_TOKEN).toString();
        jwt = JWTParser.parse(idToken);
        //o = jwt.getJWTClaimsSet().getClaim(IdTokenClaimNames.AUTH_TIME);
        //assertNotNull(o);
        
        Map<String, Object> claims = new HashMap<>(jwt.getJWTClaimsSet().getClaims());
        claims.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken);
        return claims;
    }
    
    private String getAuthCode(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol,
            Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, String> callback) throws Exception {

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
        return queryParams.getFirst(OAuth2ParameterNames.CODE); // responseType);
    }

    private MvcResult getAuthResult(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, String protocol,
            Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, String> callback, String loginRedirect) throws Exception {

        Map<String, Object> params = getAuthRequestParams(scope, state, responseType, clientId, redirectUri, nonce, optional);
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);

        MvcResult result = mockMvc
                .perform(get("/oauth2/authorize?" + rq, values).accept(MediaType.TEXT_HTML,
                        MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login"))).andReturn(); //ssi/login

        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc
                .perform(get("/ssi/login") 
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        
        assertNotNull(result.getModelAndView().getModel().get("qrUrl"));
        assertNotNull(result.getModelAndView().getModel().get("requestId"));
        assertNotNull(result.getModelAndView().getModel().get("scope"));

        session = result.getRequest().getSession(false);
        String qrUrl = result.getModelAndView().getModel().get("qrUrl").toString();
        String requestId = result.getModelAndView().getModel().get("requestId").toString();
        //String requestId = "123";

        result = mockMvc
                .perform(get(qrUrl).accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        String expectedUrl = urlBuilder.apply(requestId); 
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());
        assertEquals(expectedUrl, resultQrUrl);

        String redirectUrl = null;
        if (callback != null) {
            redirectUrl = callback.apply(session);
        }
        
        if (redirectUrl == null) {
        	result = mockMvc
                .perform(post("/login")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session)
                        .param(OAuth2ParameterNames.USERNAME, requestId).param(OAuth2ParameterNames.PASSWORD, protocol))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(loginRedirect))) //!!
                .andReturn();
        } else {
        	assertEquals(loginRedirect, redirectUrl);
        	result = mockMvc
                .perform(get(redirectUrl)
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session)
                        .param(OAuth2ParameterNames.USERNAME, requestId).param(OAuth2ParameterNames.PASSWORD, protocol))
                .andExpect(status().isOk()) 
                .andReturn();        	
        }
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
        params.put(OAuth2ParameterNames.SCOPE, scope);
        if (state != null) {
            params.put(OAuth2ParameterNames.STATE, state);
        }
        params.put(OAuth2ParameterNames.RESPONSE_TYPE, responseType);
        params.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        if (nonce != null) {
            params.put(OidcParameterNames.NONCE, nonce);
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
    
    private String getMessage(String code, Locale locale) {
        ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale);
        try {
            return resourceBundle.getString(code);
        } catch (Exception ex) {
            return code;
        }
    }

}
