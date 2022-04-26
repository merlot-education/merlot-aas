## Dynamic Client Registration

As alternative, the DCR scenario can be covered completely by our AAS implementation removing a necessity for Client to do extra calls for IAT and performing the whole scenario in synchronous way. Communication flow participants are:

- Client Service – an application or service in Client domain
- Client OCM – Organization Credential Manager (LOT3) in Client domain
- SSI Broker (SSI IAT Provider) – an endpoint from AAS in SSI domain
- SSI TSA – Trust Service API (LOT4) from SSI domain
- SSI OCM – LOT3 from SSI domain
- SSI IAM – Identity and Access Management Platform from SSI domain


An alternative DCR communication flow is:

![Dynamic Client Registration](./images/dcr.png "Dynamic Client Registration")

1.	OCM services from different domains establish trust connection between each other (some flow in Notarization or Orchestration LOTs, probably)
2.	Client Service registers with OCM in its local domain
3.	Client Service performs a dynamic registration via standard DCR endpoint in SSI AAS


