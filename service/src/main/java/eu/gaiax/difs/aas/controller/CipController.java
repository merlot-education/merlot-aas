package eu.gaiax.difs.aas.controller;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import eu.gaiax.difs.aas.service.SsiBrokerService;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
@RequestMapping("/cip")
public class CipController {

    private final SsiBrokerService ssiBrokerService;

    @ResponseBody
    @GetMapping(value = "/claims", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getClaims(@RequestParam Map<String, Object> params) { 
        String subject = (String) params.remove("sub");
        String required = (String) params.remove("req");
        return ssiBrokerService.getSubjectClaims(subject, required == null ? false : Boolean.parseBoolean(required), params);
    }
    
    // maybe will expose one more method to return claims after additional ssi authorization..  
    
}
