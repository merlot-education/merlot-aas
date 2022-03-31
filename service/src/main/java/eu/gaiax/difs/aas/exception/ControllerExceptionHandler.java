package eu.gaiax.difs.aas.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
@Slf4j
public class ControllerExceptionHandler {
    @ExceptionHandler(value = OAuth2AuthenticationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGeneralException(OAuth2AuthenticationException e, Model model) {
        log.error("Unhandled exception occurred during. Error message: {}",
                e.getMessage(),
                e.getCause());
        model.addAttribute("errorMessage", "Failed"); //custom message to render in HTML
        return "login";  //the html page in resources/templates folder
    }

    @ExceptionHandler(value = Throwable.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGeneralException(final Throwable e, final Model model) {
        log.error("Unhandled exception occurred during. Error message: {}",
                e.getMessage(),
                e.getCause());
        model.addAttribute("errorMessage", "Failed"); //custom message to render in HTML
        return "login";  //the html page in resources/templates folder
    }
}
