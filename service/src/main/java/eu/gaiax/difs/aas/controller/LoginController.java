package eu.gaiax.difs.aas.controller;

import javax.servlet.http.HttpServletRequest;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ssi")
public class LoginController {
    
    private final static Logger log = LoggerFactory.getLogger(LoginController.class);

    private final SsiBrokerService ssiBrokerService;
    
    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String login(HttpServletRequest request) {
        
        log.debug("login; got params: {}", request.getParameterMap().size());
        //log.debug("login; got state: {}", request.getParameterMap().get("state"));

        return ssiBrokerService.authorize();
    }

    @GetMapping(value = "/qr/{qrid}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQR(@PathVariable String qrid) {

        return ResponseEntity.ok(ssiBrokerService.getQR(qrid));

    }
    
    @PostMapping("/perform_login")
    public void performLogin(HttpServletRequest request) {
        
        log.debug("performLogin; got request: {}", request);

    }
}
