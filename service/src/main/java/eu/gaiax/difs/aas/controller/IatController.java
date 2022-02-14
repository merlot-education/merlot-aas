package eu.gaiax.difs.aas.controller;

import eu.gaiax.difs.aas.generated.controller.IatControllerApiDelegate;
import eu.gaiax.difs.aas.generated.model.AccessRequestDto;
import eu.gaiax.difs.aas.generated.model.AccessResponseDto;
import eu.gaiax.difs.aas.mapper.IatDtoMapper;
import eu.gaiax.difs.aas.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
public class IatController implements IatControllerApiDelegate {

    private final AuthService service;
    private final IatDtoMapper mapper;

    @Autowired
    public IatController(AuthService service, IatDtoMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    @Override
    public ResponseEntity<AccessResponseDto> postAccessRequest(AccessRequestDto accessRequestDto) {

        Map<String, Object> evaluation = service.evaluate(
                "GetIatProofInvitation",
                mapper.requestToMap(accessRequestDto));

        return ResponseEntity.ok(mapper.mapToResponse(evaluation));
    }

    @Override
    public ResponseEntity<AccessResponseDto> getAccessRequest(String requestId) {

        Map<String, Object> evaluation = service.evaluate(
                "GetIatProofResult",
                Collections.singletonMap("requestId", requestId));

        return ResponseEntity.ok(mapper.mapToResponse(evaluation));
    }

}
