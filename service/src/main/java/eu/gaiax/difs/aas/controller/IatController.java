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


//eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI2MWU0ZGU3Zi0zYmRjLTRlYjMtYjk5Mi0xODQ5YzFiOTRjZDcifQ.eyJleHAiOjAsImlhdCI6MTY0NzI2MTYxNiwianRpIjoiOTI2MDI0ZjEtOTlhZC00Yjg4LTg0MWMtOWZlOTNhMDhlY2ZkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9nYWlhLXgiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL2dhaWEteCIsInR5cCI6IkluaXRpYWxBY2Nlc3NUb2tlbiJ9.ub-AfuKxbCiCf1VfWvfmsAJbUIHjxkBljgwegj5zsAA
//lzuoEpr58ByhnWE5XNAbGNCHp2AOM1Gt

