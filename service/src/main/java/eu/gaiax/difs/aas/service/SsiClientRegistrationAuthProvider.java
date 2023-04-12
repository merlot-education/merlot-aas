package eu.gaiax.difs.aas.service;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
//import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;

public class SsiClientRegistrationAuthProvider implements AuthenticationProvider {
	
	private SsiCorsConfigurationSource corsSource;
	private AuthenticationProvider delegate;
	
	public SsiClientRegistrationAuthProvider(SsiCorsConfigurationSource corsSource, AuthenticationProvider delegate) {
		this.corsSource = corsSource;
		this.delegate = delegate;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication auth = delegate.authenticate(authentication);
		if (auth != null) {
			// can check if new client adds any new CORS origins
			// can also pass new origins to corsSource to prevent fetch from DB
			//OidcClientRegistration cliReg = ((OidcClientRegistrationAuthenticationToken) auth).getClientRegistration();
			corsSource.invalidate();
		}
		return auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return delegate.supports(authentication);
	}

}
