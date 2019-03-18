## Custom Post Authentication Handler

### Introduction / Use case.
This custom post authentication handler can be used to get the missing mandatory claim values before doing the JIT 
provisioning. 

### Applicable product versions.
Tested with WSO2 IS 5.7.0

### How to use.
1. Build the extended-post-authn-handler using the command `mvn clean install`.
2. Copy the extended-post-handler-1.0-SNAPSHOT.jar and paste in the directory, 
**<IS_Home>/repository/components/dropins**
3. Add a event listener for the custom post authentication handler under 
"Post Authentication handlers for JIT provisioning, association and for handling subject identifier"
in the identity.xml file located at **<IS_Home>/repository/conf/identity**. 
`<EventListener type="org.wso2.carbon.identity.core.handler.AbstractIdentityHandler" name="org.wso2.identity.sample.PostCustomEnrichClaimHandler" orderId="15" enable="true"/>	`

4.  Start the server.


 ### Testing the project.
Configure the federated login authentication as below, 
https://docs.wso2.com/display/IS570/Logging+in+to+your+application+via+Identity+Server+using+Facebook+Credentials
1. Configure Facebook as an IdP with JIT provisioning
2. Configured Travelocity as a SP
3. Added facebook as the login option for travelocity SP
4. Enabled "Assert identity using mapped local subject identifier" flag in the travelocity SP
5. Added following claims as a requested claim in travelocity SP
    http://wso2.org/claims/emailaddress,	
    http://wso2.org/claims/fullname,
    http://wso2.org/claims/country,	
    http://wso2.org/claims/mobile,	
    http://wso2.org/claims/organization	

Test the flow,
1. Try to login to travelocity
2. Redirected to facebook
3. Submit facebook credentials
4. Returned to IS, if it is sign-up, redirect to get mandatory claim values. 
5. Submit values for the claims.
5. Returned to travelocity, it will show values for all requested claims except organization. 
6. logout from travelocity SP. 
7. Go to management console and login as "admin/admin"
8. Update the federated user profile with organization entry. 
9. Re-login to travelocity SP.
10. Now in the travelocity all requested claims will be listed, including injected organization value. 
