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
package org.wso2.identity.sample.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.sample.PostCustomEnrichClaimHandler;

@Component(name = "org.wso2.identity.sample.component",
           immediate = true)
public class PostCustomHandlerServiceComponent {

    private static Log log = LogFactory.getLog(PostCustomHandlerServiceComponent.class);

    private static RealmService realmService;
    private static RegistryService registryService = null;

    public static RealmService getRealmService() {
        return realmService;
    }

    @Reference(name = "user.realmservice.default",
               service = RealmService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        PostCustomHandlerServiceComponent.realmService = realmService;
    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    @Reference(name = "registry.service",
               service = RegistryService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Registry Service");
        }
        PostCustomHandlerServiceComponent.registryService = registryService;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        PostAuthenticationHandler postCustomHandler = PostCustomEnrichClaimHandler.getInstance();
        ctxt.getBundleContext().registerService(PostAuthenticationHandler.class.getName(), postCustomHandler, null);

        if (log.isDebugEnabled()) {
            log.info(" Post authentication custom handler bundle is activated");

        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("Post authentication custom handler bundle is deactivated");
        }

    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
        PostCustomHandlerServiceComponent.realmService = null;
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Registry Service");
        }
        PostCustomHandlerServiceComponent.registryService = null;
    }
}
