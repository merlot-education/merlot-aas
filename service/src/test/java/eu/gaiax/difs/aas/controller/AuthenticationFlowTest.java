package eu.gaiax.difs.aas.controller;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

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
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

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
    void testLoginFlow() throws Exception {

        setupTrustService(ACCEPTED);

        MvcResult result = mockMvc.perform(
                get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}", 
                    "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app", 
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
            .andExpect(header().string("Location", containsString("/oauth2/authorize")))
            .andReturn();
        session = result.getRequest().getSession(false);

        result = mockMvc.perform(
                get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}", 
                    "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app", 
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
                .header("Authorization", "Basic YWFzLWFwcDpzZWNyZXQ=")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("code", code)
                .param("grant_type", "authorization_code")
                .param("redirect_uri", "http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint"))
            .andExpect(status().isOk())
            .andReturn();
        
        String jwtStr = result.getResponse().getContentAsString();
        JacksonJsonParser jsonParser = new JacksonJsonParser();
        String token = jsonParser.parseMap(jwtStr).get("access_token").toString();

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
    void testLoginFlowTimeout() throws Exception {

        setupTrustService(TIMED_OUT);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app",
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

        assertEquals(session.getAttribute("AUTH_ERROR"), "Login Expired");
    }

    @Test
    void testLoginFlowReject() throws Exception {

        setupTrustService(REJECTED);

        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app",
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

        assertEquals(session.getAttribute("AUTH_ERROR"), "Login Rejected");
    }

    private void setupTrustService(AccessRequestStatusDto status) {
        LocalTrustServiceClientImpl realLocaltrustServiceClient = new LocalTrustServiceClientImpl();

        Map<String, Object> loginInvitation = realLocaltrustServiceClient.evaluate("GetLoginProofInvitation", new HashMap<>());
        Map<String, Object> loginResult = realLocaltrustServiceClient.evaluate("GetLoginProofResult", new HashMap<>());
        loginResult.put("status", status);

        when(mockLocalTrustServiceClient.evaluate(eq("GetLoginProofInvitation"), anyMap()))
                .thenReturn(loginInvitation);
        when(mockLocalTrustServiceClient.evaluate(eq("GetLoginProofResult"), anyMap()))
                .thenReturn(loginResult);
    }
}
