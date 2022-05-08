package eu.gaiax.difs.aas.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.gaiax.difs.aas.client.IamClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc(addFilters = false)
public class IatProvisionFlowTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    IamClient iamClient;

    @Test
    public void testIatRequestFlow() throws Exception {
        AccessRequestDto requestDto = new AccessRequestDto()
                .subject("did:sample:1234567890")
                .entity(new ServiceAccessScopeDto().scope("openid").did("did:sample:qwerty"));
        MvcResult result = mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andReturn();
        String response = result.getResponse().getContentAsString();
        AccessResponseDto ard = objectMapper.readValue(response, AccessResponseDto.class);
        assertNull(ard.getInitialAccessToken());
        assertNotNull(ard.getRequestId());
        String requestId = ard.getRequestId();
        
        result = mockMvc.perform(
                        get("/clients/iat/requests/" + requestId)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();
        response = result.getResponse().getContentAsString();
        ard = objectMapper.readValue(response, AccessResponseDto.class);
        assertEquals(requestId, ard.getRequestId());
        assertEquals(AccessRequestStatusDto.PENDING, ard.getStatus());
        assertNull(ard.getInitialAccessToken());
        
        result = mockMvc.perform(
                        get("/clients/iat/requests/" + requestId)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();
        response = result.getResponse().getContentAsString();
        ard = objectMapper.readValue(response, AccessResponseDto.class);
        assertEquals(requestId, ard.getRequestId());
        assertEquals(AccessRequestStatusDto.PENDING, ard.getStatus());
        assertNull(ard.getInitialAccessToken());

        when(iamClient.registerIam(any(), any())).thenReturn(Map.of("registration_access_token", "keycloakIat"));
        
        result = mockMvc.perform(
                        get("/clients/iat/requests/" + requestId)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();
        response = result.getResponse().getContentAsString();
        ard = objectMapper.readValue(response, AccessResponseDto.class);
        assertEquals(requestId, ard.getRequestId());
        assertEquals(AccessRequestStatusDto.ACCEPTED, ard.getStatus());        
        assertNotNull(ard.getInitialAccessToken());
    }
    
}
