package com.ecnu.example;
import com.ecnu.OAuth2Client;
import com.ecnu.common.OAuth2Config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class AuthCodeExample {
    public static void main(String[] args) {
        SpringApplication.run(AuthCodeExample.class, args);
    }

    @Bean
    public OAuth2Client oAuth2Client() {
        OAuth2Config cf = OAuth2Config.builder()
                .clientId("client_id")
                .clientSecret("client_secret")
                .redirectUrl("http://localhost:8080/user")
                .debug(true)
                .build();
        OAuth2Client client = OAuth2Client.getClient();
        client.initOAuth2AuthorizationCode(cf);
        return client;
    }
}

@RestController
class UserController {

    @Autowired
    private OAuth2Client client;
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public void login(HttpServletResponse response) throws IOException {
        String state = client.generateRandomState();
        String authorizationUrl = client.getAuthorizationEndpoint(state);
        System.out.println(authorizationUrl);
        response.sendRedirect(authorizationUrl);
    }

    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public Map<String, String> userInfo(HttpServletRequest request) {
        // 从请求中获取userInfo
        String userInfo = (String) request.getAttribute("userInfo");
        if (userInfo == null) {
            // 如果没有userInfo，可以选择处理错误或返回一个默认值
            return  Collections.singletonMap("error", "No user information available.");
        }
        return Collections.singletonMap("message", userInfo);
    }
}

@Component
class OAuthInterceptor implements HandlerInterceptor {
    @Autowired
    private OAuth2Client client;
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String code = request.getParameter("code");
        String state = request.getParameter("state");

        String userInfo = client.getInfo(code, state);
        if (userInfo == null) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("获取用户信息失败");
            return false;
        }

        request.setAttribute("userInfo", userInfo);
        return true;
    }
}
@Configuration
class WebConfig implements WebMvcConfigurer {

    @Autowired
    private OAuthInterceptor oAuthInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册拦截器并设置拦截路径
        registry.addInterceptor(oAuthInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/login");
    }
}