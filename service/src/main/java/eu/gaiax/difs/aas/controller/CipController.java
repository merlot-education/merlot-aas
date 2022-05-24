package eu.gaiax.difs.aas.controller;

import java.util.Arrays;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
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

    // this method can be used for asynch ssi authentication too..  

    @ResponseBody
    @GetMapping(value = "/claims", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getClaims(@RequestParam Map<String, Object> params) { 
        String subject = (String) params.remove(IdTokenClaimNames.SUB);
        String scope = (String) params.remove(OAuth2ParameterNames.SCOPE);
        return ssiBrokerService.getSubjectClaims(subject, Arrays.asList(scope.split(" ")));
    }

}
