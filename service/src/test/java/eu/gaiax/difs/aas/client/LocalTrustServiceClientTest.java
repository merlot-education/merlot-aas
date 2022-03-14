package eu.gaiax.difs.aas.client;

import eu.gaiax.difs.aas.properties.LocalTrustServiceClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
public class LocalTrustServiceClientTest {

    @Autowired
    private LocalTrustServiceClientImpl localTrustServiceClient;

    @Autowired
    private LocalTrustServiceClientProperties localTrustServiceClientProperties;

    @Test
    void evaluateLoginProofInvitation() {
        Map<String, Object> expectedResponse = localTrustServiceClientProperties.getPolicyMocks().get("GetLoginProofInvitation");

        Map<String, Object> response = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        assertNotNull(response.get("requestId"));
        assertEquals(expectedResponse.get("link"), response.get("link"));
    }

    @Test
    void evaluateLoginProofResult() {
        Map<String, Object> expectedResponse = localTrustServiceClientProperties.getPolicyMocks().get("GetLoginProofResult");

        Map<String, Object> response = localTrustServiceClient.evaluate("GetLoginProofResult", Collections.emptyMap());

        assertEquals(expectedResponse.get("iss"), response.get("iss"));
        assertEquals(expectedResponse.get("sub"), response.get("sub"));
        assertEquals(expectedResponse.get("claim1"), response.get("claim1"));
    }

    @Test
    void evaluateIatProofInvitation() {
        Map<String, Object> response = localTrustServiceClient.evaluate("GetIatProofInvitation", Collections.emptyMap());

        assertNotNull(response.get("requestId"));
    }

    @Test
    void evaluateIatProofResult() {
        Map<String, Object> expectedResponse = localTrustServiceClientProperties.getPolicyMocks().get("GetIatProofResult");

        Map<String, Object> response = localTrustServiceClient.evaluate("GetIatProofResult", Collections.emptyMap());

        assertEquals(expectedResponse.get("iss"), response.get("iss"));
        assertEquals(expectedResponse.get("sub"), response.get("sub"));
        assertEquals(expectedResponse.get("claim1"), response.get("claim1"));
    }

    @Test
    void evaluateNotSameRequestId() {
        Map<String, Object> firstResponse = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        Map<String, Object> secondResponse = localTrustServiceClient.evaluate("GetLoginProofInvitation", Collections.emptyMap());

        assertNotNull(firstResponse.get("requestId"));
        assertNotNull(secondResponse.get("requestId"));
        assertNotEquals(firstResponse.get("requestId"), secondResponse.get("requestId"));
    }

}
