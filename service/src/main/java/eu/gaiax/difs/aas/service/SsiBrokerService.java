package eu.gaiax.difs.aas.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.UUID;

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
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.generated.model.ServiceAccessScopeDto;
import eu.gaiax.difs.aas.mapper.AccessRequestMapper;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SsiBrokerService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    private final TrustServiceClient trustServiceClient;
    private final AccessRequestMapper accessRequestMapper;

    public String authorize(Model model) {
        String requestID = generateRequestId();
        AccessRequestDto accessRequestDto = new AccessRequestDto()
                //.subject(requestID)
                .entity(new ServiceAccessScopeDto()); //todo
        AccessResponseDto accessResponseDto = getAccessResponseDto(accessRequestDto);

        //return getQrPage(accessResponseDto.getRequestId(), model); //todo missing link as in https://seu30.gdc-leinf01.t-systems.com/confluence/pages/viewpage.action?pageId=286628681 maybe accessResponseDto.getPolicyEvaluationResult()
        return getQrPage(requestID, model);
    }

    private String getQrPage(String requestId, Model model) {
        String qrUrl = "/ssi/qr/" + requestId + "/";
        model.addAttribute("qrUrl", qrUrl);
        model.addAttribute("requestId", requestId);

        return "login-template.html";
    }

    public byte[] getQR(String qrid) {
        QRCodeWriter barcodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = null;
        try {
            bitMatrix = barcodeWriter.encode(qrid, BarcodeFormat.QR_CODE, 200, 200);
        } catch (WriterException e) {
            e.printStackTrace();
            log.error("QR data generation failed: " + e);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ImageIO.write(MatrixToImageWriter.toBufferedImage(bitMatrix), "png", baos);
        } catch (IOException e) {
            e.printStackTrace();
            log.error("Failed to generate image from QR data: " + e);
        }
        return baos.toByteArray();
    }

    private AccessResponseDto getAccessResponseDto(AccessRequestDto accessRequestDto) {
        return accessRequestMapper.mapTologinAccessResponse(trustServiceClient.evaluate(
                "GetLoginProofInvitation",
                accessRequestMapper.loginRequestToMap(accessRequestDto)));
    }

    private String generateRequestId() {
        return UUID.randomUUID().toString();
    }


}
