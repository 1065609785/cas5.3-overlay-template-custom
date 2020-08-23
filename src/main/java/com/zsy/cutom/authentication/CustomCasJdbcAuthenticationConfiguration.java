package com.zsy.cutom.authentication;

import com.google.common.collect.Multimap;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.adaptors.jdbc.BindModeSearchDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryAndEncodeDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.SearchModeSearchDatabaseAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.config.CasJdbcAuthenticationConfiguration;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.authentication.principal.PrincipalNameTransformerUtils;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.support.password.PasswordEncoderUtils;
import org.apereo.cas.authentication.support.password.PasswordPolicyConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.*;
import org.apereo.cas.configuration.support.JpaBeans;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.HashSet;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 22:20
 */
@Configuration("CustomCasJdbcAuthenticationConfiguration")
@EnableConfigurationProperties({CasConfigurationProperties.class})
public class CustomCasJdbcAuthenticationConfiguration {
    private static final Logger LOGGER = LoggerFactory.getLogger(CasJdbcAuthenticationConfiguration.class);
    @Autowired(
            required = false
    )
    @Qualifier("queryAndEncodePasswordPolicyConfiguration")
    private PasswordPolicyConfiguration queryAndEncodePasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("searchModePasswordPolicyConfiguration")
    private PasswordPolicyConfiguration searchModePasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("queryPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration queryPasswordPolicyConfiguration;
    @Autowired(
            required = false
    )
    @Qualifier("bindSearchPasswordPolicyConfiguration")
    private PasswordPolicyConfiguration bindSearchPasswordPolicyConfiguration;
    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    @Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("personDirectoryPrincipalResolver")
    private PrincipalResolver personDirectoryPrincipalResolver;

    public CustomCasJdbcAuthenticationConfiguration() {
    }

    /*@ConditionalOnMissingBean(
            name = {"jdbcAuthenticationHandlers"}
    )*/
    @Bean
    @RefreshScope
    public Collection<AuthenticationHandler> jdbcAuthenticationHandlers() {
        Collection<AuthenticationHandler> handlers = new HashSet();
        JdbcAuthenticationProperties jdbc = this.casProperties.getAuthn().getJdbc();
        jdbc.getBind().forEach((b) -> {
            handlers.add(this.bindModeSearchDatabaseAuthenticationHandler(b));
        });
        jdbc.getEncode().forEach((b) -> {
            handlers.add(this.queryAndEncodeDatabaseAuthenticationHandler(b));
        });
        jdbc.getQuery().forEach((b) -> {
            handlers.add(this.queryDatabaseAuthenticationHandler(b));
        });
        jdbc.getSearch().forEach((b) -> {
            handlers.add(this.searchModeSearchDatabaseAuthenticationHandler(b));
        });
        return handlers;
    }

    private AuthenticationHandler bindModeSearchDatabaseAuthenticationHandler(final BindJdbcAuthenticationProperties b) {
        BindModeSearchDatabaseAuthenticationHandler h = new BindModeSearchDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), JpaBeans.newDataSource(b));
        h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.bindSearchPasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.bindSearchPasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler queryAndEncodeDatabaseAuthenticationHandler(final QueryEncodeJdbcAuthenticationProperties b) {
        QueryAndEncodeDatabaseAuthenticationHandler h = new QueryAndEncodeDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), JpaBeans.newDataSource(b), b.getAlgorithmName(), b.getSql(), b.getPasswordFieldName(), b.getSaltFieldName(), b.getExpiredFieldName(), b.getDisabledFieldName(), b.getNumberOfIterationsFieldName(), b.getNumberOfIterations(), b.getStaticSalt());
        h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.queryAndEncodePasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.queryAndEncodePasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler queryDatabaseAuthenticationHandler(final QueryJdbcAuthenticationProperties b) {
        Multimap<String, Object> attributes = CoreAuthenticationUtils.transformPrincipalAttributesListIntoMultiMap(b.getPrincipalAttributeList());
        LOGGER.debug("Created and mapped principal attributes [{}] for [{}]...", attributes, b.getUrl());
        //QueryDatabaseAuthenticationHandler h = new QueryDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), JpaBeans.newDataSource(b), b.getSql(), b.getFieldPassword(), b.getFieldExpired(), b.getFieldDisabled(), CollectionUtils.wrap(attributes));
        CustomUsernamePasswordCaptchaAuthenticationHandler h = new CustomUsernamePasswordCaptchaAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), JpaBeans.newDataSource(b), b.getSql(), b.getFieldPassword(), b.getFieldExpired(), b.getFieldDisabled(), CollectionUtils.wrap(attributes));
        h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.queryPasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.queryPasswordPolicyConfiguration);
        }

        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

    private AuthenticationHandler searchModeSearchDatabaseAuthenticationHandler(final SearchJdbcAuthenticationProperties b) {
        SearchModeSearchDatabaseAuthenticationHandler h = new SearchModeSearchDatabaseAuthenticationHandler(b.getName(), this.servicesManager, this.jdbcPrincipalFactory(), b.getOrder(), JpaBeans.newDataSource(b), b.getFieldUser(), b.getFieldPassword(), b.getTableUsers());
        h.setPasswordEncoder(PasswordEncoderUtils.newPasswordEncoder(b.getPasswordEncoder()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        h.setPrincipalNameTransformer(PrincipalNameTransformerUtils.newPrincipalNameTransformer(b.getPrincipalTransformation()));
        if (this.searchModePasswordPolicyConfiguration != null) {
            h.setPasswordPolicyConfiguration(this.searchModePasswordPolicyConfiguration);
        }

        if (StringUtils.isNotBlank(b.getCredentialCriteria())) {
            h.setCredentialSelectionPredicate(CoreAuthenticationUtils.newCredentialSelectionPredicate(b.getCredentialCriteria()));
        }

        LOGGER.debug("Created authentication handler [{}] to handle database url at [{}]", h.getName(), b.getUrl());
        return h;
    }

   /* @ConditionalOnMissingBean(
            name = {"jdbcPrincipalFactory"}
    )*/
    @Bean
    @RefreshScope
    public PrincipalFactory jdbcPrincipalFactory() {
        return PrincipalFactoryUtils.newPrincipalFactory();
    }

    /*@ConditionalOnMissingBean(
            name = {"jdbcAuthenticationEventExecutionPlanConfigurer"}
    )*/
    @Bean
    public AuthenticationEventExecutionPlanConfigurer jdbcAuthenticationEventExecutionPlanConfigurer() {
        return (plan) -> {
            this.jdbcAuthenticationHandlers().forEach((h) -> {
                plan.registerAuthenticationHandlerWithPrincipalResolver(h, this.personDirectoryPrincipalResolver);
            });
        };
    }


}
