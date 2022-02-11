package eu.gaiax.difs.aas.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.gaiax.difs.aas.generated.controller.IatControllerApiController;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(IatControllerApiController.class)
@AutoConfigureMockMvc(addFilters = false)
public class IatControllerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getIatRequest_missingRequestId_404() throws Exception {
        mockMvc.perform(
                        get("/clients/iat/request/"))
                .andExpect(status().isNotFound());
    }

    @Test
    void postIatRequest_missingAccessRequest_400() throws Exception {
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
                                        ._object(
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
                                        ._object(
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
                                        ._object(
                                                new ServiceAccessScopeDto().did("testDid")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }
}
