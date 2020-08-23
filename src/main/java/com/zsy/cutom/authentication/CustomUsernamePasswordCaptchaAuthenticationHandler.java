package com.zsy.cutom.authentication;

import com.zsy.capthcha.CustomCaptchaCredential;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apereo.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryDatabaseAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.apereo.cas.util.CollectionUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 22:15
 */
public class CustomUsernamePasswordCaptchaAuthenticationHandler  extends AbstractCustomJdbcUsernamePasswordAuthenticationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(QueryDatabaseAuthenticationHandler.class);
    private final String sql;
    private final String fieldPassword;
    private final String fieldExpired;
    private final String fieldDisabled;
    private final Map<String, Object> principalAttributeMap;

    public CustomUsernamePasswordCaptchaAuthenticationHandler(final String name, final ServicesManager servicesManager, final PrincipalFactory principalFactory, final Integer order, final DataSource dataSource, final String sql, final String fieldPassword, final String fieldExpired, final String fieldDisabled, final Map<String, Object> attributes) {
        super(name, servicesManager, principalFactory, order, dataSource);
        this.sql = sql;
        this.fieldPassword = fieldPassword;
        this.fieldExpired = fieldExpired;
        this.fieldDisabled = fieldDisabled;
        this.principalAttributeMap = attributes;
        if (StringUtils.isBlank(this.fieldPassword)) {
            LOGGER.warn("When the password field is left undefined, CAS will skip comparing database and user passwords for equality , (specially if the query results do not contain the password field),and will instead only rely on a successful query execution with returned results in order to verify credentials");
        }

    }

    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential, final String originalPassword) throws GeneralSecurityException, PreventedException {

        //验证码图片验证码
        checkImageCode((CustomCaptchaCredential) credential);

        if (!StringUtils.isBlank(this.sql) && this.getJdbcTemplate() != null) {
            Map<String, Object> attributes = new LinkedHashMap(this.principalAttributeMap.size());
            String username = credential.getUsername();
            String password = credential.getPassword();

            try {
                Map<String, Object> dbFields = this.query(credential);
                String dbExpired;
                if (!dbFields.containsKey(this.fieldPassword)) {
                    LOGGER.debug("Password field is not found in the query results. Checking for result count...");
                    if (!dbFields.containsKey("total")) {
                        throw new FailedLoginException("Missing field 'total' from the query results for " + username);
                    }

                    Object count = dbFields.get("total");
                    if (count == null || !NumberUtils.isCreatable(count.toString())) {
                        throw new FailedLoginException("Missing field value 'total' from the query results for " + username + " or value not parseable as a number");
                    }

                    Number number = NumberUtils.createNumber(count.toString());
                    if (number.longValue() != 1L) {
                        throw new FailedLoginException("No records found for user " + username);
                    }
                } else {
                    dbExpired = (String)dbFields.get(this.fieldPassword);
                    if (StringUtils.isNotBlank(originalPassword) && !this.matches(originalPassword, dbExpired) || StringUtils.isBlank(originalPassword) && !StringUtils.equals(password, dbExpired)) {
                        throw new FailedLoginException("Password does not match value on record.");
                    }
                }

                if (StringUtils.isNotBlank(this.fieldDisabled) && dbFields.containsKey(this.fieldDisabled)) {
                    dbExpired = dbFields.get(this.fieldDisabled).toString();
                    if (BooleanUtils.toBoolean(dbExpired) || "1".equals(dbExpired)) {
                        throw new AccountDisabledException("Account has been disabled");
                    }
                }

                if (StringUtils.isNotBlank(this.fieldExpired) && dbFields.containsKey(this.fieldExpired)) {
                    dbExpired = dbFields.get(this.fieldExpired).toString();
                    if (BooleanUtils.toBoolean(dbExpired) || "1".equals(dbExpired)) {
                        throw new AccountPasswordMustChangeException("Password has expired");
                    }
                }

                this.collectPrincipalAttributes(attributes, dbFields);
            } catch (IncorrectResultSizeDataAccessException var9) {
                if (var9.getActualSize() == 0) {
                    throw new AccountNotFoundException(username + " not found with SQL query");
                }

                throw new FailedLoginException("Multiple records found for " + username);
            } catch (DataAccessException var10) {
                throw new PreventedException("SQL exception while executing query for " + username, var10);
            }

            Principal principal = this.principalFactory.createPrincipal(username, attributes);
            return this.createHandlerResult(credential, principal, new ArrayList(0));
        } else {
            throw new GeneralSecurityException("Authentication handler is not configured correctly. No SQL statement or JDBC template is found.");
        }
    }

    private Map<String, Object> query(final UsernamePasswordCredential credential) {
        if (this.sql.contains("?")) {
            return this.getJdbcTemplate().queryForMap(this.sql, new Object[]{credential.getUsername()});
        } else {
            Map parameters = new LinkedHashMap();
            parameters.put("username", credential.getUsername());
            parameters.put("password", credential.getPassword());
            return this.getNamedJdbcTemplate().queryForMap(this.sql, parameters);
        }
    }

    private void collectPrincipalAttributes(final Map<String, Object> attributes, final Map<String, Object> dbFields) {
        this.principalAttributeMap.forEach((key, names) -> {
            Object attribute = dbFields.get(key);
            if (attribute != null) {
                LOGGER.debug("Found attribute [{}] from the query results", key);
                Collection<String> attributeNames = (Collection)names;
                attributeNames.forEach((s) -> {
                    LOGGER.debug("Principal attribute [{}] is virtually remapped/renamed to [{}]", key, s);
                    attributes.put(s, CollectionUtils.wrap(attribute.toString()));
                });
            } else {
                LOGGER.warn("Requested attribute [{}] could not be found in the query results", key);
            }

        });
    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof  CustomCaptchaCredential;
    }

    private void checkImageCode(CustomCaptchaCredential credential)throws GeneralSecurityException, PreventedException{
        //添加图片验证码部分start
        CustomCaptchaCredential customCaptchaCredential = credential;
        String imageCode = customCaptchaCredential.getImageCode();
        if (StringUtils.isBlank(imageCode)){
            throw new CaptchaException("图片验证码不能为空");
        }

        //这里后期可以切换为redis校验
        ServletRequestAttributes attributes1 = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        Object sessionImageCode = attributes1.getRequest().getSession().getAttribute("imageCode");
        if (sessionImageCode == null || StringUtils.isBlank(sessionImageCode.toString())){
            throw new CaptchaException("图片验证码不匹配,请重新输入图片验证码");
        }

        if(!imageCode.toLowerCase().equals(sessionImageCode.toString().toLowerCase())){
            throw new CaptchaException("图片验证码不匹配,请重新输入图片验证码");
        }

        //添加图片验证码部分end
    }

}
