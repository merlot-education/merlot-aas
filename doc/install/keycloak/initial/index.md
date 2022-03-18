## Initial keycloak setup


Keycloak (https://www.keycloak.org/) was chosen as an IAM Platform for our service deployment. Our service and test application to be protected must be registered with IAM solution properly. To setup keycloak platform the following steps must be accomplished:

- download keycloak image from the Keycloak site
- unzip downloaded archive to ${KC_HOME}
- start keycloak application using ${KC_HOME}/bin/standalone script
- open keycloak Admin console in your browser at http://localhost:8080/auth
- at first login create new user with login and password

![SSI Backhannel login](./images/ssi_backchannel_login.jpg "SSI Backchannel login")
