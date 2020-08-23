package com.zsy.cutom.authentication;

import com.google.code.kaptcha.servlet.KaptchaServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.ServletException;

/**
 * @desc
 * @Author zhaoshouyun
 * @Date 2020/8/18 22:51
 */
@Configuration
public class KaptchaConfig {
    @Bean
    public ServletRegistrationBean servletRegistrationBean() throws ServletException {
        ServletRegistrationBean servlet = new ServletRegistrationBean(new KaptchaServlet(),  "/kaptcha");//加载路径
       /* servlet.addInitParameter("kaptcha.border", "no"*//* kborder *//*);// 无边框
        servlet.addInitParameter("kaptcha.session.key", "captcha");// session key
        servlet.addInitParameter("kaptcha.textproducer.font.color", "black");
        servlet.addInitParameter("kaptcha.textproducer.font.size", "25");
        servlet.addInitParameter("kaptcha.obscurificator.impl", "com.google.code.kaptcha.impl.WaterRipple");
        servlet.addInitParameter("kaptcha.noise.impl", "com.google.code.kaptcha.impl.NoNoise");
        servlet.addInitParameter("kaptcha.image.width", "90");
        servlet.addInitParameter("kaptcha.image.height", "33");
        servlet.addInitParameter("kaptcha.textproducer.char.length", "4");
        servlet.addInitParameter("kaptcha.textproducer.char.space", "5");
        servlet.addInitParameter("kaptcha.background.clear.from", "247,247,247"); // 和登录框背景颜色一致
        servlet.addInitParameter("kaptcha.background.clear.to", "247,247,247");
*/
        servlet.addInitParameter("kaptcha.border","no");
        servlet.addInitParameter("kaptcha.session.key", "imageCode");// session key
        servlet.addInitParameter("kaptcha.border.color","105,179,90");
        servlet.addInitParameter("kaptcha.textproducer.font.color","red");
        servlet.addInitParameter("kaptcha.obscurificator.impl","com.google.code.kaptcha.impl.FishEyeGimpy");
        servlet.addInitParameter("kaptcha.image.width","250");
        servlet.addInitParameter("kaptcha.image.height","90");
        servlet.addInitParameter("kaptcha.textproducer.font.size","70");
        servlet.addInitParameter("kaptcha.textproducer.char.length","4");
        servlet.addInitParameter("kaptcha.textproducer.font.names","no");
        servlet.addInitParameter("kaptcha.border","yes");
        return servlet;
    }
}
