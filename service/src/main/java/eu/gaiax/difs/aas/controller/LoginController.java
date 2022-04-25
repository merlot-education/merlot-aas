package eu.gaiax.difs.aas.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

@Controller
@RequiredArgsConstructor
@RequestMapping("/ssi")
public class LoginController {

    private final SsiBrokerService ssiBrokerService;

    @GetMapping(value = "/login")
    public String login(HttpServletRequest request, Model model) {
        DefaultSavedRequest auth = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        model.addAttribute("scope", auth.getParameterValues("scope"));

        String[] clientId = auth.getParameterValues("client_id");

        if (clientId != null && clientId.length > 0) {
            if ("aas-app-oidc".equals(clientId[0])) {
                return oidcLogin(request, model, auth);
            }
            if ("aas-app-siop".equals(clientId[0])) {
                return ssiBrokerService.siopAuthorize(model);
            }
        }

        // TODO: sJavorsky - specify exception
        throw new RuntimeException("unknown client" + Arrays.toString(clientId));
    }

    private String oidcLogin(HttpServletRequest request, Model model, DefaultSavedRequest auth) {
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

        String errorMessage = (String) request.getSession().getAttribute("AUTH_ERROR");
        if (errorMessage != null) {
            Locale locale = (Locale) request.getSession().getAttribute("session.current.locale");
            ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale != null ? locale : Locale.getDefault());

            model.addAttribute("errorMessage", resourceBundle.getString(errorMessage));
        }
        return ssiBrokerService.authorize(model);
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

}
