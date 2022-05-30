package eu.gaiax.difs.aas.controller;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.gaiax.difs.aas.config.CustomAuthorizationRequestResolver;

@RestController
@RequestMapping()
public class DemoController {
    
    @Autowired
    private CustomAuthorizationRequestResolver authorizationRequestResolver; 
    
    @GetMapping("/demo")
    public String demonstrate(HttpServletRequest request) {
        authorizationRequestResolver.setScopes(List.of("openid"));
        return "Hi from demo app: " + getIdentity(request);
    }    

    @GetMapping("/demo/read")
    public String demonstrateRead(HttpServletRequest request) {
        authorizationRequestResolver.setScopes(List.of("openid"));
        return "Hi from demo app with read grants: " + getIdentity(request);
    }

    @GetMapping("/demo/write")
    public String demonstrateWrite(HttpServletRequest request) {
        authorizationRequestResolver.setScopes(List.of("openid"));
        return "Hi from demo app with write grants: " + getIdentity(request);
    }
    
    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // do logout manually..
        request.logout();
        //requires id_token_hint or Bearer auth..
        String redirectUrl = request.getParameter("redirect_url");
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        if (redirectUrl == null) {
            redirectUrl = "http://test-server:8990/demo";
        } else if (redirectUrl.endsWith("/read")) {
            scopes.add("profile");
        } else if (redirectUrl.endsWith("/write")) {
            scopes.add("email");
        }
        authorizationRequestResolver.setScopes(scopes);
        response.sendRedirect("http://key-server:8080/realms/gaia-x/protocol/openid-connect/logout?post_logout_redirect_uri=" + redirectUrl);
    }
    
    private String getIdentity(HttpServletRequest request) {
        return request.getUserPrincipal() == null ? null : request.getUserPrincipal().toString();
    }

}
