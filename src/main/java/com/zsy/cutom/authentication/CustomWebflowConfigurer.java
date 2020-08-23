package com.zsy.cutom.authentication;

import com.zsy.capthcha.CustomCaptchaCredential;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.configurer.DefaultLoginWebflowConfigurer;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.BinderConfiguration;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 22:44
 */
public class CustomWebflowConfigurer  extends DefaultLoginWebflowConfigurer {



    public CustomWebflowConfigurer(FlowBuilderServices flowBuilderServices,
                                    FlowDefinitionRegistry flowDefinitionRegistry, ApplicationContext applicationContext,
                                    CasConfigurationProperties casProperties) {
        super(flowBuilderServices, flowDefinitionRegistry, applicationContext, casProperties);
    }

    @Override
    protected void createRememberMeAuthnWebflowConfig(Flow flow) {
        if (casProperties.getTicket().getTgt().getRememberMe().isEnabled()) {
            createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, CustomCaptchaCredential.class);
            final ViewState state = getState(flow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM, ViewState.class);
            final BinderConfiguration cfg = getViewStateBinderConfiguration(state);
            cfg.addBinding(new BinderConfiguration.Binding("rememberMe", null, false));
            cfg.addBinding(new BinderConfiguration.Binding("imageCode", null, true));
        } else {
            createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, CustomCaptchaCredential.class);
            final ViewState state = getState(flow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM, ViewState.class);
            final BinderConfiguration cfg = getViewStateBinderConfiguration(state);
            // cfg.addBinding(new BinderConfiguration.Binding("rememberMe", null, false));
            cfg.addBinding(new BinderConfiguration.Binding("imageCode", null, true));
        }
    }

}
