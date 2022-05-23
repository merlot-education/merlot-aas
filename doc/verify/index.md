## Conformance & Verification

Some project functions were tested with [OpenID Conformance Suite](https://openid.net/certification/about-conformance-suite/), below you can find the official test suite results:

- [OpenID Connect Discovery](./config) endpoint /.well-known/openid-configuration
- [OpenID Connect Authorization](./auth) endpoint /authorize, Authorization Code Flow
- [OpenID Connect Token](./token) endpoint /token

<strong>2 Test plans were run several times locally and also at test environment:</strong>

<strong>1. OpenID Connect Core: Basic Certification Profile Authorization server test - 33 Test cases executed under this Test plan:</strong>
    
Test Name: oidcc-server
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-response-type-missing
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-userinfo-get
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-userinfo-post-header
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-userinfo-post-body
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-request-without-nonce-succeeds-for-code-flow
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-scope-profile
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-scope-email
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-scope-address
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-scope-phone
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-scope-all
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-other-scope-order-succeeds
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-display-page
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-display-popup
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-prompt-login
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-prompt-none-not-logged-in
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-prompt-none-logged-in
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-max-age-1
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-max-age-10000
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-request-with-unknown-parameter-succeeds
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-id-token-hint
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-login-hint
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ui-locales
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-claims-locales
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-request-with-acr-values-succeeds
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-codereuse
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-codereuse-30seconds
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-registered-redirect-uri
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-claims-essential
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-request-object-with-redirect-uri
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-refresh-token
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

Test Name:oidcc-ensure-request-with-valid-pkce-succeeds
Variant:client_auth_type=client_secret_basic, response_type=code, response_mode=default

<strong>2. OpenID Connect Core: Config Certification Profile Authorization server test - 1 Test case executed under this Test plan:</strong>

Test Name:oidcc-discovery-endpoint-verification
Variant:server_metadata=discovery, client_registration=static_client
