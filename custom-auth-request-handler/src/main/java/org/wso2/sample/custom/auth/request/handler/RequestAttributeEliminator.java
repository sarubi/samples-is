package org.wso2.sample.custom.auth.request.handler;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This custom class is to remove the "authenticators" query parameter if exits in the login request. The login page is
 * defined in application-authentication.xml under AuthenticationEndpointURL.
 * <AuthenticationEndpointURL>/authenticationendpoint/login.do</AuthenticationEndpointURL>
 * After removed the authentication list, then redirect to the login page. However need to customize the
 * authentication web app handle this login request and implement a custom login to return the authenticators list.
 */
public class RequestAttributeEliminator extends DefaultAuthenticationRequestHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
            throws FrameworkException {

        super.handle(request, response, context);

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();

        if (response instanceof CommonAuthResponseWrapper) {
            if (((CommonAuthResponseWrapper) response).isRedirect()) {
                String redirectUrl = ((CommonAuthResponseWrapper) response).getRedirectURL();
                if (StringUtils.isNotBlank(redirectUrl) && redirectUrl.contains(loginPage)) {
                    redirectUrl = removeAuthenticatorsQueryParam(redirectUrl);
                }
                // Set the modified redirect URL
                try {
                    response.sendRedirect(redirectUrl);
                } catch (IOException e) {
                    throw new FrameworkException("Error while redirecting to authentication endpoint.", e);
                }
            }
        }
    }

    /**
     * Remove the "authenticators" parameter and it's values.
     *
     * @param url
     * @return
     */
    private String removeAuthenticatorsQueryParam(String url) {

        return url.replaceAll("[&?]authenticators.*?(?=&|\\?|$)", "");
    }
}
