package eu.gaiax.difs.aas.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gaiax.difs.aas.client.IamClient;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc(addFilters = false)
public class IatControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    TrustServiceClient trustServiceClient;

    @MockBean
    IamClient iamClient;

    @Test
    void getRequest_missingRequestId_404() throws Exception {
        mockMvc.perform(
                        get("/clients/iat/request/"))
                .andExpect(status().isNotFound());
    }

    @Test
    void getRequest_correctRequest_pending_200() throws Exception {
        Map<String, Object> serviceResponse = Map.of(
                "iss", "responseSubject",
                "sub", "responseDid",
                "scope", "responseScope",
                "requestId", "responseRequestId",
                "status", AccessRequestStatusDto.PENDING);
        AccessResponseDto expectedResponse = new AccessResponseDto()
                .subject("responseSubject")
                .entity(new ServiceAccessScopeDto().scope("responseScope").did("responseDid"))
                .requestId("responseRequestId")
                .status(AccessRequestStatusDto.PENDING);

        when(trustServiceClient.evaluate(eq("GetIatProofResult"), any())).thenReturn(serviceResponse);

        mockMvc.perform(
                        get("/clients/iat/requests/testRequestId")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(expectedResponse), false));
    }

    @Test
    void getRequest_correctRequest_accepted_200() throws Exception {
        Map<String, Object> serviceResponse = Map.of(
                "iss", "responseSubject",
                "sub", "responseDid",
                "scope", "responseScope",
                "requestId", "responseRequestId",
                "status", AccessRequestStatusDto.ACCEPTED);
        AccessResponseDto expectedResponse = new AccessResponseDto()
                .subject("responseSubject")
                .entity(new ServiceAccessScopeDto().scope("responseScope").did("responseDid"))
                .requestId("responseRequestId")
                .status(AccessRequestStatusDto.ACCEPTED)
                .initialAccessToken("keycloakIat");

        when(trustServiceClient.evaluate(eq("GetIatProofResult"), any())).thenReturn(serviceResponse);
        when(iamClient.registerIam(any(), any())).thenReturn(Map.of("registration_access_token", "keycloakIat"));

        mockMvc.perform(
                        get("/clients/iat/requests/testRequestId")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{}"))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(expectedResponse), false));
    }

    @Test
    void postRequest_missingAccessRequest_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingServiceAccessScope_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto().subject("testSubject"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubject_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .entity(
                                                new ServiceAccessScopeDto().scope("testScope").did("testDid")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubjectDid_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .subject("testSubject")
                                        .entity(
                                                new ServiceAccessScopeDto().scope("testScope")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubjectScope_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .subject("testSubject")
                                        .entity(
                                                new ServiceAccessScopeDto().did("testDid")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_correctRequest_200() throws Exception {
        AccessRequestDto requestDto = new AccessRequestDto()
                .subject("testSubject")
                .entity(new ServiceAccessScopeDto().scope("testScope").did("testDid"));
        Map<String, Object> serviceResponse = Map.of("requestId", "responseRequestId");
        AccessResponseDto expectedResponse = new AccessResponseDto()
                .requestId("responseRequestId")
                .entity(new ServiceAccessScopeDto());

        when(trustServiceClient.evaluate(eq("GetIatProofInvitation"), any())).thenReturn(serviceResponse);

        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(expectedResponse), false));
    }

}
