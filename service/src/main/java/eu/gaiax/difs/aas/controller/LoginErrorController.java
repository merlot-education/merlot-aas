package eu.gaiax.difs.aas.controller;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
@RequiredArgsConstructor
public class LoginErrorController implements ErrorController {

    private final SsiBrokerService ssiBrokerService;

    @RequestMapping("/error")
    public String loginError(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        String errorMessage = null;
        if (session != null) {
            OAuth2AuthenticationException ex = (OAuth2AuthenticationException) session
                    .getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
            if (ex != null) {
                errorMessage = ex.getError().getErrorCode();
            }
        }
        model.addAttribute("errorMessage", errorMessage);
        return ssiBrokerService.authorize(model);
    }
}
