package eu.gaiax.difs.aas.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ssi")
public class LoginController {
    
    private final SsiBrokerService ssiBrokerService;
    
    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String login(HttpServletRequest request) {
        return ssiBrokerService.authorize();
    }
    
    @GetMapping(value = "/qr/{qrid}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQR(@PathVariable String qrid) {
        return ResponseEntity.ok(ssiBrokerService.getQR(qrid));
    }

    @GetMapping("/userinfo")
    public void userInfo(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ssiBrokerService.userInfo(request, response);
    }
    
}
