package eu.gaiax.difs.aas.client;

import eu.gaiax.difs.aas.properties.LocalTrustServiceClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
public class LocalTrustServiceClientTest {
    @Autowired
    private LocalTrustServiceClientImpl localTrustServiceClient;
    @Autowired
    private LocalTrustServiceClientProperties localTrustServiceClientProperties;

    @Test
    void localTrustServiceClientTest() {
        localTrustServiceClientProperties.getPolicyMocks().keySet().forEach(policy -> {
            Map<String, Object> result = localTrustServiceClient.evaluate(policy, Collections.emptyMap());
            Map<String, Object> expectedResult = localTrustServiceClientProperties.getPolicyMocks().get(policy);

            assertTrue(areEqual(result, expectedResult));
        });
    }

    private boolean areEqual(Map<String, Object> first, Map<String, Object> second) {
        if (first.size() != second.size()) {
            return false;
        }

        return first.entrySet().stream()
                .allMatch(e -> e.getValue().equals(second.get(e.getKey())));
    }
}
