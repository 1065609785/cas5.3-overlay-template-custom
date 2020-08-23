package com.zsy.cutom.authentication;

import javax.security.auth.login.AccountException;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 23:46
 */
public class CaptchaException  extends AccountException {
    public CaptchaException() {
        super();
        // TODO Auto-generated constructor stub
    }

    public CaptchaException(String msg) {
        super(msg);
        // TODO Auto-generated constructor stub
    }

}
