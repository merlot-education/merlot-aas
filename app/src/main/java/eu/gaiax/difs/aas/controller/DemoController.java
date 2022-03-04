package eu.gaiax.difs.aas.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {
    
    @GetMapping
    public String demonstrate(HttpServletRequest request) {
        return "Hi from demo app";
    }    

}
