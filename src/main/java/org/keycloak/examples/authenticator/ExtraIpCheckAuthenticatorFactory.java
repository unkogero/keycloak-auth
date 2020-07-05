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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ExtraIpCheckAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "extra-ipcheck-authenticator";
    private static final ExtraIpCheckAuthenticator SINGLETON = new ExtraIpCheckAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty propertyIpChk;
        propertyIpChk = new ProviderConfigProperty();
        propertyIpChk.setName("IPCHECK");
        propertyIpChk.setLabel("IPアドレスチェック");
        propertyIpChk.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        propertyIpChk.setHelpText("IPアドレスチェックによる追加認証を実施するかをチェックします。");
        configProperties.add(propertyIpChk);

        ProviderConfigProperty propertyIp;
        propertyIp = new ProviderConfigProperty();
        propertyIp.setName("IPADDRESS");
        propertyIp.setLabel("IPアドレス");
        propertyIp.setType(ProviderConfigProperty.STRING_TYPE);
        propertyIp.setHelpText("追加認証を実施しないIPアドレスを指定します。");
        configProperties.add(propertyIp);
    }


    @Override
    public String getHelpText() {
        return "Extra IP Check.";
    }

    @Override
    public String getDisplayType() {
        return "Extra IP Check";
    }

    @Override
    public String getReferenceCategory() {
        return "Extra IP Check";
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }


}
