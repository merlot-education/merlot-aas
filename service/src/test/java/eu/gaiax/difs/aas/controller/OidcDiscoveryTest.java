package eu.gaiax.difs.aas.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.junit.jupiter.api.Assertions.assertEquals;


@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
public class OidcDiscoveryTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getDiscoveryConfig_scopes() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn();

        List<String> supportedScopes = new ArrayList<>();

        objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("scopes_supported")
                .elements()
                .forEachRemaining(jsonNode -> supportedScopes.add(jsonNode.asText()));

        assertEquals(List.of("first", "second"), supportedScopes);
    }

    @Test
    void getDiscoveryConfig_claims() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn();

        List<String> supportedClaims = new ArrayList<>();

        objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("claims_supported")
                .elements()
                .forEachRemaining(jsonNode -> supportedClaims.add(jsonNode.asText()));

        assertEquals(List.of("one", "three", "two"), supportedClaims);
    }

}
