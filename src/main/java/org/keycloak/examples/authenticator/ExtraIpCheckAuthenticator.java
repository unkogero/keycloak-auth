/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.examples.authenticator;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.ServerCookie;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ExtraIpCheckAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(ExtraIpCheckAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        String localAddr = context.getConnection().getLocalAddr();
        int localPort = context.getConnection().getLocalPort();
        String remoteAddr = context.getConnection().getRemoteAddr();
        int remotePort = context.getConnection().getRemotePort();

        logger.debug("[TEST]local addr:" + localAddr + " port:" + String.valueOf(localPort));
        logger.debug("[TEST]Remote addr:" + remoteAddr + " port:" + String.valueOf(remotePort));
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Boolean checkIp = Boolean.valueOf(config.getConfig().get("IPCHECK"));
        String chkIpStr = config.getConfig().get("IPADDRESS");

        logger.debug("[TEST]checkIp:" + checkIp);
        logger.debug("[TEST]NonCheck ipAddess:" + chkIpStr);

        String[] chkIpAddresses = chkIpStr.split("-", 0);
        Boolean chkIp = false;
        for( String str : chkIpAddresses ){
            logger.debug("[TEST]chkIpAddres:" + str);
            if( remoteAddr.equals(str) ) {
                logger.debug("[TEST]check true");
                chkIp = true;
                break;
            }
        }

        ////
        KeycloakSession session = context.getSession();
        UserSessionProvider sessionprovider = session.getProvider(UserSessionProvider.class);
        List<UserSessionModel> uslist = sessionprovider.getUserSessions(context.getRealm(), context.getUser());
        
        logger.debug("[TEST]uslist.size="+ uslist.size() );
        uslist.forEach((e) -> {
            logger.debug("[TEST]v client IP=" + e.getIpAddress() );
        });

        if (chkIp) {
            context.success();
            return;
        }

        context.attempted();

    }

    @Override
    public void action(AuthenticationFlowContext context) {

        logger.debug("[TEST]action call:");
    }


    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return null;
    }

    @Override
    public void close() {

    }
}
