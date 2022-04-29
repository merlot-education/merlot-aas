package eu.gaiax.difs.aas.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
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
    public ResponseEntity<Void> siopCallback(@RequestParam MultiValueMap<String, Object> body) {

        String error;
        Map<String, Object> claims;
        String idToken = (String) body.getFirst("id_token");
        if (idToken == null) {
            error = (String) body.getFirst("error");
            String desc = (String) body.getFirst("error_description");
            if (error != null || desc != null) {
                claims = new HashMap<>();
                claims.put("error", String.join(": ", error, desc));
                claims.put("state", (String) body.getFirst("state"));
            } else {
                return ResponseEntity.badRequest().build();
            }
        } else {

            try {
                JWT jwt = JWTParser.parse(idToken);
                claims = jwt.getJWTClaimsSet().getClaims();
            } catch (ParseException ex) {
                // log it?
                JacksonJsonParser parser = new JacksonJsonParser();
                claims = parser.parseMap(idToken);
            }
        }
        
        error = ssiBrokerService.processSiopLoginResponse(claims);
        if (error == null) {
            return ResponseEntity.ok().build();
        }
        // TODO: return error..
        return ResponseEntity.badRequest().build();
    }
}
