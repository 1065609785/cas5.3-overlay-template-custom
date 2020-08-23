package com.zsy.cutom.authentication;

import com.zsy.capthcha.CustomCaptchaCredential;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.handler.PrincipalNameTransformer;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.support.password.PasswordPolicyConfiguration;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

/**
 * @desc 重写父类
 * @Author zhaoshouyun
 * @Date 2020/8/18 23:14
 */
public abstract class AbstractCustomUsernamePasswordAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractUsernamePasswordAuthenticationHandler.class);
    protected AuthenticationPasswordPolicyHandlingStrategy passwordPolicyHandlingStrategy = (o, o2) -> {
        return new ArrayList(0);
    };
    private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();
    private PrincipalNameTransformer principalNameTransformer = (formUserId) -> {
        return formUserId;
    };
    private PasswordPolicyConfiguration passwordPolicyConfiguration;

    public AbstractCustomUsernamePasswordAuthenticationHandler(final String name, final ServicesManager servicesManager, final PrincipalFactory principalFactory, final Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    protected AuthenticationHandlerExecutionResult doAuthentication(final Credential credential) throws GeneralSecurityException, PreventedException {
        //UsernamePasswordCredential originalUserPass = (UsernamePasswordCredential)credential;
        CustomCaptchaCredential originalUserPass = (CustomCaptchaCredential)credential;
        //UsernamePasswordCredential userPass = new UsernamePasswordCredential(originalUserPass.getUsername(), originalUserPass.getPassword());
        CustomCaptchaCredential userPass = new CustomCaptchaCredential();
        userPass.setImageCode(originalUserPass.getImageCode());
        userPass.setRememberMe(originalUserPass.isRememberMe());
        userPass.setPassword(originalUserPass.getPassword());
        userPass.setUsername(originalUserPass.getUsername());
        if (StringUtils.isBlank(userPass.getUsername())) {
            throw new AccountNotFoundException("Username is null.");
        } else {
            LOGGER.debug("Transforming credential username via [{}]", this.principalNameTransformer.getClass().getName());
            String transformedUsername = this.principalNameTransformer.transform(userPass.getUsername());
            if (StringUtils.isBlank(transformedUsername)) {
                throw new AccountNotFoundException("Transformed username is null.");
            } else if (StringUtils.isBlank(userPass.getPassword())) {
                throw new FailedLoginException("Password is null.");
            } else {
                LOGGER.debug("Attempting to encode credential password via [{}] for [{}]", this.passwordEncoder.getClass().getName(), transformedUsername);
                String transformedPsw = this.passwordEncoder.encode(userPass.getPassword());
                if (StringUtils.isBlank(transformedPsw)) {
                    throw new AccountNotFoundException("Encoded password is null.");
                } else {
                    userPass.setUsername(transformedUsername);
                    userPass.setPassword(transformedPsw);
                    LOGGER.debug("Attempting authentication internally for transformed credential [{}]", userPass);
                    return this.authenticateUsernamePasswordInternal(userPass, originalUserPass.getPassword());
                }
            }
        }
    }

    protected abstract AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException;

    public boolean supports(final Credential credential) {
        if (!UsernamePasswordCredential.class.isInstance(credential)) {
            LOGGER.debug("Credential is not one of username/password and is not accepted by handler [{}]", this.getName());
            return false;
        } else if (this.credentialSelectionPredicate == null) {
            LOGGER.debug("No credential selection criteria is defined for handler [{}]. Credential is accepted for further processing", this.getName());
            return true;
        } else {
            LOGGER.debug("Examining credential [{}] eligibility for authentication handler [{}]", credential, this.getName());
            boolean result = this.credentialSelectionPredicate.test(credential);
            LOGGER.debug("Credential [{}] eligibility is [{}] for authentication handler [{}]", new Object[]{credential, this.getName(), BooleanUtils.toStringTrueFalse(result)});
            return result;
        }
    }

    protected boolean matches(final CharSequence charSequence, final String password) {
        return this.passwordEncoder.matches(charSequence, password);
    }

    public void setPasswordPolicyHandlingStrategy(final AuthenticationPasswordPolicyHandlingStrategy passwordPolicyHandlingStrategy) {
        this.passwordPolicyHandlingStrategy = passwordPolicyHandlingStrategy;
    }

    public void setPasswordEncoder(final PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public void setPrincipalNameTransformer(final PrincipalNameTransformer principalNameTransformer) {
        this.principalNameTransformer = principalNameTransformer;
    }

    public void setPasswordPolicyConfiguration(final PasswordPolicyConfiguration passwordPolicyConfiguration) {
        this.passwordPolicyConfiguration = passwordPolicyConfiguration;
    }

    public AuthenticationPasswordPolicyHandlingStrategy getPasswordPolicyHandlingStrategy() {
        return this.passwordPolicyHandlingStrategy;
    }

    public PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }

    public PrincipalNameTransformer getPrincipalNameTransformer() {
        return this.principalNameTransformer;
    }

    public PasswordPolicyConfiguration getPasswordPolicyConfiguration() {
        return this.passwordPolicyConfiguration;
    }

}
