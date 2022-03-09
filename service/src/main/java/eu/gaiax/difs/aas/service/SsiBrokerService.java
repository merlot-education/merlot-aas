package eu.gaiax.difs.aas.service;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SsiBrokerService {

    private final static Logger log = LoggerFactory.getLogger(SsiBrokerService.class);

    private final TrustServiceClient trustServiceClient;
    private final AccessRequestMapper accessRequestMapper;
    private final AuthenticationManager authenticationManager;

    private final HttpMessageConverter<OidcUserInfo> userInfoHttpMessageConverter =
            new OidcUserInfoHttpMessageConverter();
    private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
            new OAuth2ErrorHttpMessageConverter();

    public String authorize(Model model) {
        AccessRequestDto accessRequestDto = new AccessRequestDto()
                .subject(generateRequestId())
                .entity(new ServiceAccessScopeDto()); //todo

        AccessResponseDto accessResponseDto = evaluateLogin(accessRequestDto);

        return getQrPage(accessResponseDto.getRequestId(), model); //todo missing link as in https://seu30.gdc-leinf01.t-systems.com/confluence/pages/viewpage.action?pageId=286628681 maybe accessResponseDto.getPolicyEvaluationResult()
    }

    private String generateRequestId() {
        return UUID.randomUUID().toString();
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

    private AccessResponseDto evaluateLogin(AccessRequestDto accessRequestDto) {
        return accessRequestMapper.mapTologinAccessResponse(
                trustServiceClient.evaluate(
                        "GetLoginProofInvitation",
                        accessRequestMapper.loginRequestToMap(accessRequestDto)));
    }

    public void userInfo(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            Authentication principal = SecurityContextHolder.getContext().getAuthentication();

            OidcUserInfoAuthenticationToken userInfoAuthentication = new OidcUserInfoAuthenticationToken(principal);

            OidcUserInfoAuthenticationToken userInfoAuthenticationResult =
                    (OidcUserInfoAuthenticationToken) this.authenticationManager.authenticate(userInfoAuthentication);

            sendUserInfoResponse(response, userInfoAuthenticationResult.getUserInfo());

        } catch (OAuth2AuthenticationException ex) {
            sendErrorResponse(response, ex.getError());
        } catch (Exception ex) {
            OAuth2Error error = new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OpenID Connect 1.0 UserInfo Error: " + ex.getMessage(),
                    "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError");
            sendErrorResponse(response, error);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void sendUserInfoResponse(HttpServletResponse response, OidcUserInfo userInfo) throws IOException {
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.userInfoHttpMessageConverter.write(userInfo, null, httpResponse);
    }

    private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
        HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
        if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_TOKEN)) {
            httpStatus = HttpStatus.UNAUTHORIZED;
        } else if (error.getErrorCode().equals(OAuth2ErrorCodes.INSUFFICIENT_SCOPE)) {
            httpStatus = HttpStatus.FORBIDDEN;
        }
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        httpResponse.setStatusCode(httpStatus);
        this.errorHttpResponseConverter.write(error, null, httpResponse);
    }

}
