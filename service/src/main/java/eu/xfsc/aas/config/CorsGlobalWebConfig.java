package eu.xfsc.aas.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsGlobalWebConfig implements WebMvcConfigurer {
    @Value("${cors.global.origins}")
    private String[] corsGlobalOrigins;
    @Value("${cors.global.patterns}")
    private String[] corsGlobalPatterns;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(corsGlobalOrigins)
                .allowedOriginPatterns(corsGlobalPatterns)
                .allowedMethods("*");
    }
}