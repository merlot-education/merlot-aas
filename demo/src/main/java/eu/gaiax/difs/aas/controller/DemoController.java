package eu.gaiax.difs.aas.controller;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping()
public class DemoController {

    @GetMapping
    public String root(HttpServletRequest request) {
        return "Hi from app root: " + getIdName(request);
    }    
    
    @GetMapping("/demo")
    public String demonstrate(HttpServletRequest request) {
        return "Hi from demo app: " + getIdName(request);
    }    

    @GetMapping("/demo/read")
    public String getBooks(HttpServletRequest request) {
        return "Hi from demo app with read grants: " + getIdName(request);
    }

    @GetMapping("/demo/write")
    public String getManager(HttpServletRequest request) {
        return "Hi from demo app with write grants: " + getIdName(request);
    }
/*
    @GetMapping(value = "/logout")
    public String logout() throws ServletException {
        request.logout();
        return "redirect:/";
    }
*/
    private String getIdName(HttpServletRequest request) {
        KeycloakSecurityContext ctx = getKeycloakSecurityContext(request);
        if (ctx == null) {
            return null;
        }
        return ctx.getIdToken().getGivenName();
    }

    /**
     * The KeycloakSecurityContext provides access to several pieces of information
     * contained in the security token, such as user profile information.
     */
    private KeycloakSecurityContext getKeycloakSecurityContext(HttpServletRequest request) {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }

}

