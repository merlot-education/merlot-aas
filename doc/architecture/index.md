## AAS Architecture Overview

Major AAS components and other GAIA-X services involved in communication with AAS are presented on the diagram below:

![AAS Components](./images/aas_component_model.png "AAS Component Model")

The components are:
- Authentication Server: major AAS component exposing endpoints required by GAIA-X LOT1 specification
- IAM Platform: Identity and Access Management platform like keycloak, Gluu, WSO2, etc. 
- Portal: web application protected with AAS, implemented as GAIA-X LOT13
- Personal Credential manager: mobile application (SSI Wallet), GAIA-X LOT2 implementation
- Organization Credential Manager: GAIA-X LOT3 implementation
- Trust Services API: GAIA-X LOT4 implementation

The Authentication Server is implemented as a regular Spring Boot Java application. Required OpenID/OAuth2 functionality is provided by [Spring Authorization Server](https://docs.spring.io/spring-security-oauth2-boot/docs/2.2.x-SNAPSHOT/reference/html/boot-features-security-oauth2-authorization-server.html) with help of Spring Security components. AAS implements several interfaces, more details about their functionality and implementation can be found in the [AAS Functions section](../functions)