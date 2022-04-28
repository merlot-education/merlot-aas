package eu.gaiax.difs.aas.controller;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.imageio.ImageIO;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
public class AuthenticationFlowTest {

    @MockBean
    private TrustServiceClient mockLocalTrustServiceClient;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testOidcLoginFlow() throws Exception {

        setupTrustService(ACCEPTED);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
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
        String qrUrl = result.getModelAndView().getModel().get("qrUrl").toString();
        String userId = result.getModelAndView().getModel().get("requestId").toString();

        result = mockMvc.perform(
                        get(qrUrl)
                                .accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        String expectedUrl = "uri://" + userId;
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());

        assertEquals(expectedUrl, resultQrUrl);

        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", userId))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/authorize")))
                .andReturn();

        session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/gaia-x/broker/ssi-oidc/endpoint")))
                .andReturn();

        String reUrl = result.getResponse().getRedirectedUrl();
        MultiValueMap<String, String> params = UriComponentsBuilder.fromUriString(reUrl).build().getQueryParams();
        String code = params.getFirst("code");

        result = mockMvc.perform(
                        post("/oauth2/token")
                                .header("Authorization", "Basic YWFzLWFwcC1vaWRjOnNlY3JldA==")
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .param(OAuth2ParameterNames.CODE, code)
                                .param(OAuth2ParameterNames.GRANT_TYPE, "authorization_code")
                                .param(OAuth2ParameterNames.REDIRECT_URI, "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint"))
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
        // check session.getMaxInactiveInterval() too?

        String accessToken = jwt.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        String idToken = jwt.get(OidcParameterNames.ID_TOKEN).toString();

        // now test session evaluation..
        result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}" +
                                        "&max_age={age}&id_token_hint={hint}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "10", idToken)
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        //.session((MockHttpSession) session)
                )
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();

        session = result.getRequest().getSession(false);

        mockMvc.perform(
                        get("/ssi/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();

        // TODO: call to /userinfo doesn't work because of auth issue on /jwks endpoint
        // but it works from oidc auth flow, and we do provide /userinfo endpoint
        // so, will investigate it later..
        //result = mockMvc.perform(
        //        get("/userinfo")
        //        .header("Authorization", "Bearer " + token)
        //        .accept(MediaType.APPLICATION_JSON))
        //    .andExpect(status().isOk())
        //    .andDo(print())
        //    .andReturn();
    }

    @Test
    void testSiopLoginFlow() throws Exception {

        setupTrustService(ACCEPTED);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A")
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
        String userId = result.getModelAndView().getModel().get("requestId").toString();
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
                "&client_id=http://auth-server:9000" +
                "&redirect_uri=http://auth-server:9000/ssi/siop-cb" +
                "&response_mode=post" +
                "&nonce=" + userId;
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());

        assertEquals(expectedUrl, resultQrUrl);

        result = mockMvc.perform(
                        post("/login")
                                .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .cookie(new Cookie("JSESSIONID", session.getId()))
                                .session((MockHttpSession) session)
                                .param("username", userId))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/authorize")))
                .andReturn();

        session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A")
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
                                .param(OAuth2ParameterNames.REDIRECT_URI, "http://key-server:8080/realms/gaia-x/broker/ssi-siop/endpoint"))
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

    private String decodeQR(byte[] content) throws IOException, ChecksumException, NotFoundException, FormatException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        return new QRCodeReader().decode(bitmap).getText();
    }

    @Test
    void testLoginFlowTimeout() throws Exception {

        setupTrustService(TIMED_OUT);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
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
                                .param("username", userId))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        session = result.getRequest().getSession(false);

        assertEquals(session.getAttribute("AUTH_ERROR"), "loginExpired");
    }

    @Test
    void testLoginFlowReject() throws Exception {

        setupTrustService(REJECTED);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
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
                                .param("username", userId))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login")))
                .andReturn();
        session = result.getRequest().getSession(false);

        assertEquals(session.getAttribute("AUTH_ERROR"), "loginRejected");
    }

    private void setupTrustService(AccessRequestStatusDto status) {
        LocalTrustServiceClientImpl realLocalTrustServiceClient = new LocalTrustServiceClientImpl();

        Map<String, Object> loginInvitation = realLocalTrustServiceClient.evaluate("GetLoginProofInvitation", new HashMap<>());
        Map<String, Object> loginResult = realLocalTrustServiceClient.evaluate("GetLoginProofResult", new HashMap<>());
        loginResult.put("status", status);

        when(mockLocalTrustServiceClient.evaluate(eq("GetLoginProofInvitation"), anyMap()))
                .thenReturn(loginInvitation);
        when(mockLocalTrustServiceClient.evaluate(eq("GetLoginProofResult"), anyMap()))
                .thenReturn(loginResult);
    }
}
