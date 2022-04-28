package eu.gaiax.difs.aas.exception;

import org.springframework.security.core.AuthenticationException;

public class AssLoginException extends AuthenticationException {
    public AssLoginException(String message) {
        super(message);
    }
}
