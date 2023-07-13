/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.xfsc.aas.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The OpenApi Spring config
 */
@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {

    private final Optional<BuildProperties> buildProperties;

    @Bean
    OpenAPI openApiInfo() {
        String version;
        String securitySchemeName = "bearerAuth";
        
        if (buildProperties.isPresent()) {
            version = buildProperties.get().getVersion();
        } else {
            version = "Development Build";
        }

        return new OpenAPI().info(new Info().version(version).title("GAIA-X Authentication & Authorization Service")
                .description("The API to bridge existing IAM solutions with SSI-based authentication.")
                .license(new License().name("Apache 2.0").url("http://www.apache.org/licenses/LICENSE-2.0")))
        		.addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(
                        new Components()
                            .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                    .name(securitySchemeName)
                                    .type(SecurityScheme.Type.HTTP)
                                    .scheme("bearer")
                                    .bearerFormat("JWT")
                           )
                );
    }
    
}
