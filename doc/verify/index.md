## Conformance & Verification

Some project functions were tested with [OpenID Conformance Suite](https://openid.net/certification/about-conformance-suite/), below you can find the official test suite results:

- [OpenID Connect Discovery](./config) endpoint: /.well-known/openid-configuration
- [OpenID Connect Authorization](./auth) endpoints: /oauth2/authorize, /oauth2/jwks, /oauth2/token, /userinfo

A number of pen-tests were applied to the service, see [Penetration test results](./pentest) 

JMetter [Load tests and results](./load)

<br><br>
<strong>Following requirements were tested manually, Jira Xray used as a Test repository</strong>

<strong>Tests:</strong>

- PIP Integration functionality

- Credential Based Access Control (CrBac) functionality

- Different TSA statuses

- DM.AA.00020 SSI Login Page - SSI SIOP Broker

- IDM.AA.00026 Standard IAM Compatibility

- IDM.AA.00025 Policy based authorization

- IDM.AA.00024 Offer SSI Client Registration Auth API

- M.AA.00021 QR Code Generation - SSI OIDC Broker

- DM.AA.00020 SSI Login Page - SSI OIDC Broker

- IDM.AA.00015 External PIP Integration

- IDM.AA.00014 Credential Based Access Control (CrBac)

<strong>Results for test execution:</strong> <a href="test_execution_results.PNG">Manual tests RESULTS</a>
