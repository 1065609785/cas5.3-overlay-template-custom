package com.zsy.capthcha;

import org.apereo.cas.authentication.RememberMeUsernamePasswordCredential;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 20:54
 */

public class CustomCaptchaCredential extends RememberMeUsernamePasswordCredential {

    //图片验证码code
    private String imageCode;

    public String getImageCode() {
        return imageCode;
    }

    public void setImageCode(String imageCode) {
        this.imageCode = imageCode;
    }
}
