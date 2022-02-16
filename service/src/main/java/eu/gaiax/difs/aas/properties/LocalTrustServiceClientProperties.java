package eu.gaiax.difs.aas.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Map;

@Data
@Component
@Profile("local")
@ConfigurationProperties(prefix = "application.local-trust-service-client")
public class LocalTrustServiceClientProperties {
    private Map<String, Map<String, Object>> policyMocks;
}
