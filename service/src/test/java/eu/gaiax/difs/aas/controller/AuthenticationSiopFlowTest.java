package eu.gaiax.difs.aas.controller;

import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.service.SsiBrokerService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

import static eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto.*;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
public class AuthenticationSiopFlowTest {

    @Autowired
    private MockMvc mockMvc;

//    @Mock
//    SsiBrokerService ssiBrokerService;

    @Test
    void testOidcLoginFlow() throws Exception {
        MvcResult result = mockMvc.perform(
                        get("/oauth2/authorize?scope={scope}&state={state}&response_type={type}&client_id={id}&redirect_uri={uri}&nonce={nonce}",
                                "openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-siop",
                                "http://key-server:8080/realms/gaia-x/broker/ssi-siop/endpoint", "fXCqL9w6_Daqmibe5nD7Rg")
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

        result = mockMvc.perform(
                        post("/ssi/siop-callback").contentType(APPLICATION_FORM_URLENCODED_VALUE).content("id_token={ \"iss\": \"https://self-issued.me/v2\", " +
                                                                                                        "\"sub\": \"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\", " +
                                                                                                        "\"aud\": \"https://auth-server:9000/ssi/siop-cb\", " +
                                                                                                        "\"nonce\": \"n-0S6_WzA2Mj\", \"exp\": 1311281970, \"iat\": 1311280970}"))
                .andExpect(status().isOk())
                .andReturn();
        session = result.getRequest().getSession(false);
    }
}
