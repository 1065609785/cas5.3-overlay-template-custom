package com.zsy.capthcha;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.MessageDescriptor;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 22:03
 */
public class CustomUsernamePasswordCaptchaAuthenticationHandlerBak extends AbstractPreAndPostProcessingAuthenticationHandler {

    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    JdbcTemplate jdbcTemplate;
    String sql ;

    public CustomUsernamePasswordCaptchaAuthenticationHandlerBak(final String name, final ServicesManager servicesManager, final PrincipalFactory principalFactory, final Integer order, JdbcTemplate jdbcTemplate, String sql) {
        super(name, servicesManager, principalFactory, order);
        this.jdbcTemplate =jdbcTemplate;
        this.sql = sql;
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(Credential credential) throws GeneralSecurityException, PreventedException {
        CustomCaptchaCredential customCaptchaCredential = (CustomCaptchaCredential) credential;
        String imageCode = customCaptchaCredential.getImageCode();
        if (StringUtils.isBlank(imageCode)){
            throw new FailedLoginException("图片验证码不能为空");
        }

        //这里后期可以切换为redis校验
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        Object sessionImageCode = attributes.getRequest().getSession().getAttribute("imageCode");
        if (sessionImageCode == null || StringUtils.isBlank(sessionImageCode.toString())){
            throw new FailedLoginException("图片验证码不匹配,请重新输入图片验证码");
        }

        if(!imageCode.toLowerCase().equals(sessionImageCode.toString().toLowerCase())){
            throw new FailedLoginException("图片验证码不匹配,请重新输入图片验证码");
        }
        Map<String, Object> userInfo = this.jdbcTemplate.queryForMap(this.sql, new Object[]{customCaptchaCredential.getUsername()});

        if (userInfo == null){
            throw new AccountNotFoundException("用户名或密码错误");
        }
        if (encoder.matches(customCaptchaCredential.getPassword(),userInfo.get("password").toString()))
        {
            // 返回多属性
           // Map<String, Object> map = new HashMap<>();
            //map.put("username", customCaptchaCredential.getUsername());
            userInfo.put("password",null);
            List<MessageDescriptor> warning = new ArrayList<MessageDescriptor>();
            return createHandlerResult(customCaptchaCredential, principalFactory.createPrincipal(customCaptchaCredential.getUsername(), userInfo),
                warning);
        }
        throw new FailedLoginException("密码不匹配");
    }

   /* @Override
    public boolean preAuthenticate(Credential credential) {
        return false;
    }

    @Override
    public AuthenticationHandlerExecutionResult postAuthenticate(Credential credential, AuthenticationHandlerExecutionResult result) {
        return result;
    }*/

    //判断是否支持自定义用户密码相关信息
    @Override
    public boolean supports(Credential credential) {
        return credential instanceof CustomCaptchaCredential;
    }
}
