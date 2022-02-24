package eu.gaiax.difs.aas.config;

import eu.gaiax.difs.aas.client.LocalTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.RestTrustServiceClientImpl;
import eu.gaiax.difs.aas.client.TrustServiceClient;
import java.awt.image.BufferedImage;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;

@Configuration
public class TrustServiceClientConfig {

    @Bean
    @Profile("prod")
    public TrustServiceClient restTrustServiceClient() {
        return new RestTrustServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public TrustServiceClient localTrustServiceClient() {
        return new LocalTrustServiceClientImpl();
    }

    @Bean
    public HttpMessageConverter<BufferedImage> createImageHttpMessageConverter() {
        return new BufferedImageHttpMessageConverter();
    }    
}
