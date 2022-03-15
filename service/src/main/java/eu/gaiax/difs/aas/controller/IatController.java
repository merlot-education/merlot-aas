package eu.gaiax.difs.aas.controller;

import eu.gaiax.difs.aas.generated.controller.IatControllerApiDelegate;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.mapper.AccessRequestMapper;
import eu.gaiax.difs.aas.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class IatController implements IatControllerApiDelegate {

    private final AuthService authService;
    private final AccessRequestMapper mapper;

    @Autowired
    public IatController(AuthService authService, AccessRequestMapper mapper) {
        this.authService = authService;
        this.mapper = mapper;
    }

    @Override
    public ResponseEntity<AccessResponseDto> postAccessRequest(AccessRequestDto accessRequestDto) {

        Map<String, Object> evaluation = authService.evaluate("GetIatProofInvitation",
                mapper.iatRequestToMap(accessRequestDto));

        return ResponseEntity.ok(mapper.mapToIatAccessResponse(evaluation));
    }

    @Override
    public ResponseEntity<AccessResponseDto> getAccessRequest(String requestId) {

        Map<String, Object> evaluation = authService.evaluate("GetIatProofResult", mapper.iatRequestToMap(requestId));

        return ResponseEntity.ok(mapper.mapToIatAccessResponse(evaluation));
    }

}

