package com.zsy.capthcha;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.QueryJdbcAuthenticationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 21:28
 */
//@Configuration("customUsernamePasswordCaptchaConfig")
//@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomUsernamePasswordCaptchaConfig  implements AuthenticationEventExecutionPlanConfigurer {
   // QueryJdbcAuthenticationProperties
    /*@Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    private ServicesManager servicesManager;*/
    @Override
    public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {

    }
}
