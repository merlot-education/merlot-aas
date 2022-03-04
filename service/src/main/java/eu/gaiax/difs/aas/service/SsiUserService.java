package eu.gaiax.difs.aas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class SsiUserService implements UserDetailsService { //, OAuth2UserService<OidcUserRequest, OidcUser> {
    
    private static final Logger log = LoggerFactory.getLogger(SsiUserService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("loadUserByUserName.enter; got username: {}", username);
        UserDetails ud = User.withUsername(username)
                .password("{noop}") //password
                .authorities("ANY")
                .build();
        log.debug("loadUserByUserName.exit; returning: {}", ud);
        return ud;
    }

    //@Override
    //public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
    //    log.debug("load.enter; got user: {}", userRequest);
    ///    UserDetails dt = loadUserByUsername("user");
    //    return new DefaultOidcUser(dt.getAuthorities(), userRequest.getIdToken(), 
    //            OidcUserInfo.builder().email("test@test.com").build());
    //}

}
