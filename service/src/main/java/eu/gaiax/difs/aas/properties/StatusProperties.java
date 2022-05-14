package eu.gaiax.difs.aas.properties;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import eu.gaiax.difs.aas.client.TrustServicePolicy;
import eu.gaiax.difs.aas.generated.model.AccessRequestStatusDto;
import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "aas.tsa")
public class StatusProperties {

    private Map<TrustServicePolicy, AccessRequestStatusDto> statuses;
    
    public AccessRequestStatusDto getPolicyStatus(TrustServicePolicy policy) {
        return statuses.get(policy);
    }
    
    public void setPolicyStatus(TrustServicePolicy policy, AccessRequestStatusDto status) {
        statuses.put(policy, status);
    }

}
