package eu.gaiax.difs.aas.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

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
public class SsiController {
    
    private static final Logger log = LoggerFactory.getLogger(SsiController.class);

    private final SsiBrokerService ssiBrokerService;

    @GetMapping(value = "/login")
    public String login(HttpServletRequest request, Model model) {
        DefaultSavedRequest auth = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        String lang = request.getParameter("lang");
        Locale locale; 
        if (lang == null) {
            locale = (Locale) request.getSession().getAttribute("session.current.locale");
            if (locale == null) {
                locale = request.getLocale();
            }
        } else {
            locale = Locale.forLanguageTag(lang);
        }
        
        if (auth == null) {
            log.debug("login; session attributes: {}", request.getSession().getAttributeNames());
            model.addAttribute("errorMessage", getErrorMessage("sessionTimeout", locale));
            return "login-template.html";
        }
        
        model.addAttribute(OAuth2ParameterNames.SCOPE, auth.getParameterValues(OAuth2ParameterNames.SCOPE));
        String error = request.getParameter(OAuth2ParameterNames.ERROR);
        if (error != null) {
            model.addAttribute("errorMessage", getErrorMessage(error, locale));
        }

        String[] clientId = auth.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (clientId != null && clientId.length > 0) {
            if ("aas-app-siop".equals(clientId[0])) {
                ssiBrokerService.siopAuthorize(model.asMap());
            } else {
                //if ("aas-app-oidc".equals(clientId[0])) {
                    String[] age = auth.getParameterValues("max_age");
                    if (age != null && age.length > 0) {
                        model.addAttribute("max_age", age[0]);
                    }
    
                    String[] hint = auth.getParameterValues("id_token_hint");
                    if (hint != null && hint.length > 0) {
                        String sub = getSubject(hint[0]);
                        if (sub != null) {
                            model.addAttribute(IdTokenClaimNames.SUB, sub);
                        }
                    }
    
                    ssiBrokerService.oidcAuthorize(model.asMap());
                }
            //}
            return "login-template.html";
        }

        throw new OAuth2AuthenticationException("unknown client: " + (clientId == null ? null : Arrays.toString(clientId)));
    }
    
    private String getErrorMessage(String errorCode, Locale locale) {
        ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale);
        try {
            return resourceBundle.getString(errorCode);
        } catch (Exception ex) {
            log.warn("login.error; no resource found for error: {}", errorCode);
        }
        return errorCode;
    }

    private String getSubject(String idToken) {
        try {
            JWT jwt = JWTParser.parse(idToken);
            return jwt.getJWTClaimsSet().getSubject();
        } catch (Exception ex) {
            log.debug("getSubject; cannot parse JWT: {}", idToken);
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

    @ResponseBody
    @PostMapping(value = "/siop-callback", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public void siopCallback(@RequestParam MultiValueMap<String, Object> body) {

        String error;
        Map<String, Object> claims;
        String idToken = (String) body.getFirst(OidcParameterNames.ID_TOKEN);
        if (idToken == null) {
            error = (String) body.getFirst(OAuth2ParameterNames.ERROR);
            String desc = (String) body.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
            if (error != null || desc != null) {
                claims = new HashMap<>();
                claims.put(OAuth2ParameterNames.ERROR, String.join(": ", error, desc));
                String nonce = (String) body.getFirst(OidcParameterNames.NONCE);
                if (nonce == null) {
                    nonce = (String) body.getFirst(OAuth2ParameterNames.STATE);
                }
                claims.put(OidcParameterNames.NONCE, nonce);
            } else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: no id_token nor error provided"); 
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
        
        ssiBrokerService.processSiopLoginResponse(claims);
    }
    
}
