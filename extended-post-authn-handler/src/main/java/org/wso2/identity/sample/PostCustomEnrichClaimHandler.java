/*
 *   Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.identity.sample;

import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.identity.sample.internal.PostCustomHandlerServiceComponent;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom post authentication handler to handle the missing claims values before JIT provisioning.
 */
public class PostCustomEnrichClaimHandler extends AbstractPostAuthnHandler {

    private static final Log log = LogFactory.getLog(PostCustomEnrichClaimHandler.class);
    private static volatile PostCustomEnrichClaimHandler instance = new PostCustomEnrichClaimHandler();

    public static PostCustomEnrichClaimHandler getInstance() {

        return instance;
    }

    @Override
    public int getPriority() {

        return 15;
    }

    @Override
    public String getName() {

        return "PostCustomHandler";
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws PostAuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Post custom authentication handling started");
        }

        if (getAuthenticatedUser(context) == null) {
            if (log.isDebugEnabled()) {
                log.debug("No authenticated user found. Hence returning without handling custom claims handling");
            }
            return PostAuthnHandlerFlowStatus.UNSUCCESS_COMPLETED;
        }

        boolean isEnrichmentRequestTriggered = isEnrichRequestTriggered(context);
        if (!isEnrichmentRequestTriggered) {
            PostAuthnHandlerFlowStatus flowStatus = handleCustomPostAuthenticationRequest(request, response, context);
            return flowStatus;
        } else {
            handleCustomPostAuthenticationHandlerResponse(request, response, context);
            if (log.isDebugEnabled()) {
                log.debug("Successfully returning from custom claim handler");
            }
            return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
        }
    }

    private boolean isEnrichRequestTriggered(AuthenticationContext context) {

        Object object = context.getProperty(Constants.ENRICHMENT_TRIGGERED);
        boolean isEnrichRequestTriggered = false;
        if (object != null && object instanceof Boolean) {
            isEnrichRequestTriggered = (boolean) object;
        }
        return isEnrichRequestTriggered;
    }

    /**
     * Handle post authentication request where redirect to get missing claim values if its needed.
     *
     * @param request
     * @param response
     * @param context
     * @return
     * @throws PostAuthenticationFailedException
     */
    private PostAuthnHandlerFlowStatus handleCustomPostAuthenticationRequest(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context) throws PostAuthenticationFailedException {

        // If no step failed at authentication we should do post authentication work (e.g. enrich claim handling etc)
        if (context.isRequestAuthenticated()) {

            if (log.isDebugEnabled()) {
                log.debug("Request is successfully authenticated");
            }

            if (Constants.IS_ENRICHMENT_TRIGGERED_ENABLED) {
                // Get missing claims from external APIs.
                String missingClaims = getMissingClaims(context, request, response);

                // Getting required criteria to redirect, to get values for missing claims.
                Map<String, String> conditions = getRequiredConditionsToRedirect(context);
                boolean isUserExist = Boolean.parseBoolean(conditions.get("isUserExist"));
                boolean federationFlow = Boolean.parseBoolean(conditions.get("federationFlow"));
                boolean isJitProvisioningEnabled = Boolean.parseBoolean(conditions.get("isJitProvisioningEnabled"));

                if (!isUserExist && federationFlow && isJitProvisioningEnabled && StringUtils
                        .isNotBlank(missingClaims)) {
                    redirectToGetMissingClaims(response, context, missingClaims);
                    return PostAuthnHandlerFlowStatus.INCOMPLETE;
                } else {
                    return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
                }
            }
        }
        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
    }

    /**
     * Redirect to get missing claims values.
     *
     * @param response
     * @param context
     * @param missingClaims
     * @throws PostAuthenticationFailedException
     */
    private void redirectToGetMissingClaims(HttpServletResponse response, AuthenticationContext context,
            String missingClaims) throws PostAuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Mandatory claims missing, " + missingClaims);
        }
        try {
            URIBuilder uriBuilder = new URIBuilder(
                    ConfigurationFacade.getInstance().getAuthenticationEndpointMissingClaimsURL());
            uriBuilder.addParameter(FrameworkConstants.MISSING_CLAIMS, missingClaims);
            uriBuilder.addParameter(FrameworkConstants.SESSION_DATA_KEY, context.getContextIdentifier());
            uriBuilder.addParameter(FrameworkConstants.REQUEST_PARAM_SP,
                    context.getSequenceConfig().getApplicationConfig().getApplicationName());
            uriBuilder.addParameter("spTenantDomain", context.getTenantDomain());
            response.sendRedirect(uriBuilder.build().toString());
            context.setProperty(Constants.ENRICHMENT_TRIGGERED, true);
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to outside to enrich claims");
            }
        } catch (IOException e) {
            throw new PostAuthenticationFailedException("Error while handling enrich claims",
                    "Error while redirecting to request claims page", e);
        } catch (URISyntaxException e) {
            throw new PostAuthenticationFailedException("Error while handling enrich claims",
                    "Error while building redirect URI", e);
        }
    }

    /**
     * Handle post authentication response, extract missing claims and values from response and set it as local claims.
     *
     * @param request
     * @param response
     * @param context
     */
    private void handleCustomPostAuthenticationHandlerResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Starting to process the response with enrich claims");
        }

        Map<String, String> enrichedClaims = new HashMap<String, String>();

        Map<String, String[]> requestParams = request.getParameterMap();
        for (String key : requestParams.keySet()) {
            if (key.startsWith(FrameworkConstants.RequestParams.MANDOTARY_CLAIM_PREFIX)) {

                String localClaimURI = key.substring(FrameworkConstants.RequestParams.MANDOTARY_CLAIM_PREFIX.length());
                enrichedClaims.put(localClaimURI, requestParams.get(key)[0]);
            }
        }

        // Here, idea is to pass enriched claims map to the provisioning handler, so directly set enriched claims to
        // local claim values. (i.e. UNFILTERED_LOCAL_CLAIM_VALUES).
        Map<String, String> localClaimValues = (Map<String, String>) context
                .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);
        localClaimValues.putAll(enrichedClaims);
        context.setProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES, localClaimValues);
    }

    /**
     * Call to external APIs to get missing claims details for a user.
     *
     * @param context
     * @param request
     * @param response
     * @return
     */
    private String getMissingClaims(AuthenticationContext context, HttpServletRequest request,
            HttpServletResponse response) {

        // Check with external endpoint and validate which are missing user claims
        // Format should be string that contains claim URIs in comma separated way

        // Use Test values
        String TEST_CLAIMS = "http://wso2.org/claims/country,http://wso2.org/claims/displayName,http://wso2.org/claims/mobile";
        return TEST_CLAIMS;
    }

    /**
     * Get authenticated user from context.
     *
     * @param authenticationContext
     * @return
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext authenticationContext) {

        AuthenticatedUser user = authenticationContext.getSequenceConfig().getAuthenticatedUser();
        return user;
    }

    /**
     * Get required conditions to redirect to get the missing claims.
     *
     * @param context
     * @return
     * @throws PostAuthenticationFailedException
     */
    private Map<String, String> getRequiredConditionsToRedirect(AuthenticationContext context)
            throws PostAuthenticationFailedException {

        Map<String, String> conditions = new HashedMap();
        SequenceConfig sequenceConfig = context.getSequenceConfig();
        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig config = entry.getValue();
            AuthenticatorConfig authenticatorConfig = config.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig.getApplicationAuthenticator();

            if (authenticator instanceof FederatedApplicationAuthenticator) {
                conditions.put("federationFlow", "true");
                ExternalIdPConfig externalIdPConfig = null;
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(config.getAuthenticatedIdP(), context.getTenantDomain());
                    context.setExternalIdP(externalIdPConfig);
                } catch (IdentityProviderManagementException e) {
                    new FrameworkException("Error while checking user existence", e);
                }
                boolean isJitProvisioningEnabled = externalIdPConfig.isProvisioningEnabled();
                conditions.put("isJitProvisioningEnabled", String.valueOf(isJitProvisioningEnabled));

                if (config.isSubjectIdentifierStep()) {
                    AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
                    boolean isUserExist = isUserExist(authenticatedUser, externalIdPConfig);
                    conditions.put("isUserExist", String.valueOf(isUserExist));
                    if (isUserExist) {
                        break;
                    }
                }
            }
        }
        return conditions;
    }

    /**
     * Check whether user is exist in user store or not.
     *
     * @param authenticatedUser
     * @param externalIdPConfig
     * @return
     * @throws PostAuthenticationFailedException
     */
    private boolean isUserExist(AuthenticatedUser authenticatedUser, ExternalIdPConfig externalIdPConfig)
            throws PostAuthenticationFailedException {

        boolean isUserExist = false;

        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        try {
            String provisioningUserStoreId = externalIdPConfig.getProvisioningUserStoreId();
            UserRealm realm = getUserRealm(authenticatedUser.getTenantDomain());
            UserStoreManager userStoreManager = realm.getUserStoreManager()
                    .getSecondaryUserStoreManager(provisioningUserStoreId);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            isUserExist = userStoreManager.isExistingUser(tenantAwareUsername);
        } catch (UserStoreException e) {
            new FrameworkException("Error while checking user existence", e);
        }
        return isUserExist;
    }

    /**
     * Get user realm.
     *
     * @param tenantDomain
     * @return
     * @throws PostAuthenticationFailedException
     */
    private UserRealm getUserRealm(String tenantDomain) throws PostAuthenticationFailedException {

        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(PostCustomHandlerServiceComponent.getRegistryService(),
                    PostCustomHandlerServiceComponent.getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new PostAuthenticationFailedException("Error while handling enrich claims",
                    "Error occurred while retrieving the Realm for " + tenantDomain + " to handle local claims", e);
        }
        return realm;
    }
}
