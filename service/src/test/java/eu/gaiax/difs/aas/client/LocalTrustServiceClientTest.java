package eu.gaiax.difs.aas.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class LocalTrustServiceClientTest {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    
    @Autowired
    private LocalTrustServiceClientImpl localTrustServiceClient;

    @Test
    void evaluateLoginProofInvitation() {
        Map<String, Object> response = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        assertNotNull(response.get("requestId"));
        assertNotNull(response.get("link"));
    }

    @Test
    void evaluateLoginProofResult() {
        Map<String, Object> response = localTrustServiceClient.evaluate("GetLoginProofResult", Map.of("requestId", "testRequestId"));

        assertEquals(issuerUri, response.get("iss"));
        assertEquals("testRequestId", response.get("requestId"));
        assertEquals("testRequestId", response.get("sub"));
        assertEquals(AccessRequestStatusDto.PENDING, response.get("status"));
    }

    @Test
    void evaluateIatProofInvitation() {
        Map<String, Object> response = localTrustServiceClient.evaluate("GetIatProofInvitation", Collections.emptyMap());

        assertNotNull(response.get("requestId"));
    }

    @Test
    void evaluateIatProofResult() {
        Map<String, Object> response = localTrustServiceClient.evaluate("GetIatProofResult", Map.of("requestId", "testRequestId"));

        assertEquals(issuerUri, response.get("iss"));
        assertEquals("testRequestId", response.get("requestId"));
        assertEquals("testRequestId", response.get("sub"));
        assertEquals(AccessRequestStatusDto.PENDING, response.get("status"));
    }

    @Test
    void evaluateNotSameRequestId() {
        Map<String, Object> firstResponse = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        Map<String, Object> secondResponse = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        assertNotNull(firstResponse.get("requestId"));
        assertNotNull(secondResponse.get("requestId"));
        assertNotEquals(firstResponse.get("link"), secondResponse.get("link"));
        assertNotEquals(firstResponse.get("requestId"), secondResponse.get("requestId"));
    }

}
