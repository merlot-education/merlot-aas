package eu.gaiax.difs.aas.controller;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import java.awt.image.BufferedImage;
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

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

@RestController
@RequestMapping("/ssi")
public class LoginController {
    
    private final static Logger log = LoggerFactory.getLogger(LoginController.class);
    
    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String login(HttpServletRequest request) {
        
        log.debug("login; got params: {}", request.getParameterMap().size());
        //log.debug("login; got state: {}", request.getParameterMap().get("state"));

        String qrid = UUID.randomUUID().toString();
        return "<html>\n" + 
                "<header><title>SSI Login</title></header>\n" +
                "<body>\n" +
                    "<h1>Login with SSI</h1>\n" +
                    //"<img alt=\"Scan QR code with SSI wallet\" src=\"/ssi/qr/" + qrid + "\" />\n" +
                    "<form name='f' action=\"/ssi/perform_login\" method='POST'>\n" +
                      "<table>\n" +
                        "<tr>\n" +
                          "<td><img alt=\"Scan QR code with your SSI wallet\" src=\"/ssi/qr/" + qrid + "\"/></td>\n" +
                        "</tr>\n" +
                        "<tr>\n" +
                          "<td><input type=\"submit\" value=\"Login\"/></td>\n" +
                        "</tr>\n" +
                      "</table>\n" +
                    "</form>\n" +
                "</body>\n" + 
            "</html>";
    }
    
    @GetMapping("/qr/{qrid}") //, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<BufferedImage> getQR(@PathVariable String qrid) throws Exception {
        QRCodeWriter barcodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = barcodeWriter.encode(qrid, BarcodeFormat.QR_CODE, 200, 200);
        return ResponseEntity.ok(MatrixToImageWriter.toBufferedImage(bitMatrix));        
    }
    
    @PostMapping("/perform_login")
    public void performLogin(HttpServletRequest request) {
        
        log.debug("performLogin; got request: {}", request);
        
    }
    

}
