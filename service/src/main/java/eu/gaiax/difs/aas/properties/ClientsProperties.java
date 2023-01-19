package eu.gaiax.difs.aas.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "aas.iam")
public class ClientsProperties {

    private Map<String, ClientProperties> clients;
    
    @Getter
    @Setter
    public static class ClientProperties {

        private String id;

        private String secret;

        private Set<String> redirectUris;

        @Override
        public String toString() {
            return "{id=" + id + ", secret=" + secret + ", redirectUris=" + redirectUris + "}";
        }
        
    }

    @Override
    public String toString() {
        return "ClientsProperties " + clients;
    }

}
