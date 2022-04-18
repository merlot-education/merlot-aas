package eu.gaiax.difs.aas.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.imageio.ImageIO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import eu.gaiax.difs.aas.client.TrustServiceClient;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SsiBrokerService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    private final TrustServiceClient trustServiceClient;

    public String authorize(Model model) {
        log.debug("authorize.enter; got model: {}", model);
        
        Map<String, Object> params = new HashMap<>();
        params.put("namespace", "Login");

        Set<String> scopes = new HashSet<>();
        scopes.add("openid");
        Object o = model.getAttribute("scope");
        if (o != null) {
            String[] sa = (String[]) o;
            scopes.addAll(Arrays.asList(sa));
        }
        params.put("scope", scopes);
        
        // they can be provided in re-login scenario..
        o = model.getAttribute("not_older_than");
        if (o != null) {
            params.put("not_older_than", o);
        }
        o = model.getAttribute("max_age");
        if (o != null) {
            params.put("max_age", o);
        }
        
        Map<String, Object> result = trustServiceClient.evaluate("GetLoginProofInvitation", params);
        String link = (String) result.get("link");
        String requestId = (String) result.get("requestId");
        
        // encode link otherwise it'll not pass security check
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes()); 
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);
        
        log.debug("authorize.exit; returning model: {}", model);
        return "login-template.html";
    }

    public byte[] getQR(String elink) {
        // the incoming link is encoded, we must decode it first
        log.debug("getQR.enter; got elink: {}", elink);
        String link = new String(Base64.getUrlDecoder().decode(elink));
        QRCodeWriter barcodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = null;
        try {
            bitMatrix = barcodeWriter.encode(link, BarcodeFormat.QR_CODE, 200, 200);
        } catch (WriterException e) {
            log.error("getQR.error; QR data generation failed", e);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ImageIO.write(MatrixToImageWriter.toBufferedImage(bitMatrix), "png", baos);
        } catch (IOException e) {
            log.error("getQR.error; Failed to generate image from QR data", e);
        }
        log.debug("getQR.exit; returning image for link: {}", link);
        return baos.toByteArray();
    }

}
