package eu.gaiax.difs.aas.controller;

import javax.servlet.http.HttpServletRequest;

import eu.gaiax.difs.aas.service.SsiUserService;
import io.swagger.v3.oas.annotations.Parameter;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.json.JsonParser;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;

import java.util.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/ssi")
public class LoginController {

    private final SsiBrokerService ssiBrokerService;

    @GetMapping(value = "/login")
    public String login(HttpServletRequest request, Model model) {
        DefaultSavedRequest auth = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        model.addAttribute("scope", auth.getParameterValues("scope"));

        String errorMessage = (String) request.getSession().getAttribute("AUTH_ERROR");
        if (errorMessage != null) {
            Locale locale = (Locale) request.getSession().getAttribute("session.current.locale");
            ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale != null ? locale : Locale.getDefault());
            model.addAttribute("errorMessage", resourceBundle.getString(errorMessage));
        }

        String[] clientId = auth.getParameterValues("client_id");

        if (clientId != null && clientId.length > 0) {
            if ("aas-app-oidc".equals(clientId[0])) {
                return oidcLogin(model, auth);
            }
            if ("aas-app-siop".equals(clientId[0])) {
                return ssiBrokerService.siopAuthorize(model);
            }
        }

        throw new OAuth2AuthenticationException("unknown client: " + (clientId == null ? "null" : Arrays.toString(clientId)));
    }

    private String oidcLogin(Model model, DefaultSavedRequest auth) {
        String[] age = auth.getParameterValues("max_age");
        if (age != null && age.length > 0) {
            model.addAttribute("max_age", age[0]);
        }

        String[] hint = auth.getParameterValues("id_token_hint");
        if (hint != null && hint.length > 0) {
            String sub = getSubject(hint[0]);
            if (sub != null) {
                model.addAttribute("sub", sub);
            }
        }

        return ssiBrokerService.oidcAuthorize(model);
    }

    private String getSubject(String idToken) {
        try {
            JWT jwt = JWTParser.parse(idToken);
            return jwt.getJWTClaimsSet().getSubject();
        } catch (Exception ex) {
            // log it.. then assume idToken is String
            // better have it in local var. but don't know is it thread-safe or not..
            JacksonJsonParser jsonParser = new JacksonJsonParser();
            Map<String, Object> params = jsonParser.parseMap(idToken);
            return (String) params.get(IdTokenClaimNames.SUB);
        }
    }

    @GetMapping(value = "/qr/{qrid}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQR(@PathVariable String qrid) {

        return ResponseEntity.ok(ssiBrokerService.getQR(qrid));

    }

    @PostMapping(value = "/siop-callback", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ResponseEntity siopLogin(
            @Parameter(description = "Request ID", required = true)
            @RequestParam("id_token") final String idToken) {
//        @RequestParam("id_token") final Map<String, String> idToken) {

            JacksonJsonParser parser = new JacksonJsonParser(); //todo why above does not work and when creating custom converter it clashes with already build in converter - of course

        ssiBrokerService.processSiopLoginResponse(parser.parseMap(idToken));

        return ResponseEntity.ok().build();

    }
}
