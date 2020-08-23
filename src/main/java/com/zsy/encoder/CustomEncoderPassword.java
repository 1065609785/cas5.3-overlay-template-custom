package com.zsy.encoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/16 17:11
 */

public class CustomEncoderPassword implements PasswordEncoder {
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomEncoderPassword.class);
    //建议使用security 里的加密
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public String encode(CharSequence textPassword) {
        String encode =encoder.encode(textPassword);
        LOGGER.info("明文：[{}]，加过密后的密文：[{}]",textPassword,encode);
        return encode;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        boolean matches = encoder.matches(rawPassword, encodedPassword);
        LOGGER.info("密码比对结果：{}",matches);
        return matches;
    }

    public static void main(String[] args) {
        String textPassword = "123456";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encode = encoder.encode(textPassword);
        System.out.println(encode);
    }
}
