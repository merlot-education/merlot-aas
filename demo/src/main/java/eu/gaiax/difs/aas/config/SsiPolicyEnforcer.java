package eu.gaiax.difs.aas.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.authorization.KeycloakAdapterPolicyEnforcer;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.authorization.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SsiPolicyEnforcer extends PolicyEnforcer {
    
    private static final Logger log = LoggerFactory.getLogger(SsiPolicyEnforcer.class);
    
    private KeycloakDeployment deployment;

    public SsiPolicyEnforcer(KeycloakDeployment deployment, AdapterConfig adapterConfig) {
        super(deployment, adapterConfig);
        this.deployment = deployment;
    }
    
    @Override
    public AuthorizationContext enforce(OIDCHttpFacade facade) {
        /*
        log.debug("enforce.enter; facade: {}", facade);
        boolean updated = false;

        // setup facade
        KeycloakSecurityContext keycloakSecurityContext = getKeycloakSecurityContext();

        if (keycloakSecurityContext instanceof RefreshableKeycloakSecurityContext) {
            RefreshableKeycloakSecurityContext refreshableSecurityContext = (RefreshableKeycloakSecurityContext) keycloakSecurityContext;

            // just in case session got serialized
            //if (refreshableSecurityContext.getDeployment() == null) {
            //    log.trace("Recreating missing deployment and related fields in deserialized context");
            //    AdapterTokenStore adapterTokenStore = adapterTokenStoreFactory.createAdapterTokenStore(deployment, (HttpServletRequest) facade.getRequest(),
            //            (HttpServletResponse) facade.getResponse());
            //    refreshableSecurityContext.setCurrentRequestInfo(deployment, adapterTokenStore);
            //}

            //if (!refreshableSecurityContext.isActive() || deployment.isAlwaysRefreshToken()) {
            //    if (refreshableSecurityContext.refreshExpiredToken(false)) {
            //        ((HttpServletRequest) facade.getRequest()).setAttribute(KeycloakSecurityContext.class.getName(), refreshableSecurityContext);
            //    } else {
            //        //clearAuthenticationContext();
            //    }
            //}

            //WrappedHttpServletRequest request = (WrappedHttpServletRequest) facade.getRequest();
            //((HttpServletRequest) facade.getRequest()).setAttribute(KeycloakSecurityContext.class.getName(), keycloakSecurityContext);
            updated = true;
        }
        log.debug("enforce; facade updated: {} with context: {}", updated, keycloakSecurityContext);
        return super.enforce(facade);
        */
        log.debug("Policy enforcement is enabled. Enforcing policy decisions for path [{}].", facade.getRequest().getURI());

        AuthorizationContext context = new SsiKeycloakPolicyEnforcer(this).authorize(facade);

        log.debug("Policy enforcement result for path [{}] is : {}", facade.getRequest().getURI(), context.isGranted() ? "GRANTED" : "DENIED");
        log.debug("Returning authorization context with permissions:");
        for (Permission permission : context.getPermissions()) {
            log.debug("permission: {}", permission);
        }

        return context;
    }
    
    private KeycloakSecurityContext getKeycloakSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            Object principal = authentication.getPrincipal();

            if (principal instanceof KeycloakPrincipal) {
                return KeycloakPrincipal.class.cast(principal).getKeycloakSecurityContext();
            }
        }

        return null;
    }
    
}
