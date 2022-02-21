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

package eu.gaiax.difs.aas.config;

import static org.springframework.security.config.Customizer.withDefaults;

//import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The Spring Security config.
 */
@EnableWebSecurity //(debug = true)
public class SecurityConfig {
	
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //http.requestMatcher(EndpointRequest.toAnyEndpoint())  // actuator endpoints
        //        .authorizeRequests((requests) -> requests.anyRequest().permitAll()) // hasRole("ENDPOINT_ADMIN"));
        //        .authorizeRequests().antMatchers("*/oauth2/**").permitAll()
        //        .and()
        //        .formLogin(withDefaults())
                //.oauth2Login(withDefaults())
        //        ;
    	
        http
        	.csrf().disable()
        	.authorizeRequests()
        	.antMatchers(
                    "/api/**", "/*.ico", "/*.png",
                    "/webjars/springfox-swagger-ui/**",
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/swagger-resources/**",
                    "/actuator", "/actuator/**",
                    "/oauth2/**", "/.well-known/**", 
                    "/error", "/login"
                )
                .permitAll()
        	
            .anyRequest().authenticated()
        	.and()
        	.formLogin(withDefaults())
        	//.oauth2Login(withDefaults())
        	;
        return http.build();
    }
    
}

