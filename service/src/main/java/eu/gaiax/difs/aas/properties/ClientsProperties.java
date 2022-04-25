package eu.gaiax.difs.aas.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "aas.iam.clients")
public class ClientsProperties {

    private ClientProperties oidc;

    private ClientProperties siop;

    @Getter
    @Setter
    public static class ClientProperties {

        private String id;

        private String secret;

        private String redirectUri;

    }

}
