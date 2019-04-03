## Request Attribute Eliminator

### Introduction / Use case.
This custom class is to remove the "authenticators" query parameter if exits in the login URL where the URL is defined 
in application-authentication.xml under AuthenticationEndpointURL property.
`<AuthenticationEndpointURL>/authenticationendpoint/login.do</AuthenticationEndpointURL>`
After removing the authentication list, we redirect to the login page. However need to customize the login page that 
is in authentication web application to handle this this type of login request and needs implement a custom login 
to return the authenticators list.

### Applicable product versions.
Tested with WSO2 IS 5.2.0

### How to use.
1. Build the custom-authn-request-handler using the command `mvn clean install`.
2. Copy the org.wso2.sample.custom.auth.request.handler-1.0-SNAPSHOT.jar and paste in the directory, 
**<IS_Home>/repository/components/lib**
3. Replace with extended custom handler for AuthenticationRequestHandler Extensions 
in the application-authentication.xml file located at **<IS_Home>/repository/conf/identity**. 
`		<AuthenticationRequestHandler>org.wso2.sample.custom.auth.request.handler.RequestAttributeEliminator</AuthenticationRequestHandler>`

4.  Start the server.
5. Need to customize the login.jsp to obtain the authenticator list for given SP. For testing purpose I manually 
added few authenticators in login.jsp.
    ` idpAuthenticatorMapping =  new HashMap();
     idpAuthenticatorMapping.put("facebook", "FacebookAuthenticator");
     idpAuthenticatorMapping.put("wso2", "SAMLSSOAuthenticator") ;
     idpAuthenticatorMapping.put("LOCAL", "BasicAuthenticator") ;`


 ### Testing the project.

1. Configured Travelocity as a SP
2. Configure multi option login for travelocity SP in first step. (basic authenticator + facebook or etc)
3. Enable samal tracer
4. Try to login to travelocity
5. Redirected to /authenticationendpoint/login.do
6. Analyse the /authenticationendpoint/login.do request, where we can not see authenticators parameter even though we
 added multi option login. 
7. In UI you will see basic authenticator with list of multi option federated authenticators.