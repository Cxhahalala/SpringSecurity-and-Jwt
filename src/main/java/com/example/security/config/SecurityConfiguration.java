package com.example.security.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http
                .csrf(csrf -> csrf.disable()) //禁用csrf
                // 配置请求授权规则
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/api/v1/auth/**").permitAll()  //白名单url不需要验证
                        .requestMatchers("/api/v1/demo-controller").hasRole("admin")
                        .anyRequest().authenticated() //其它路径需要认证
                )
                //配置会话管理策略为无状态，认证信息依赖与每一次的jwt
                .sessionManagement(session ->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //配置自定义认证提供者
                .authenticationProvider(authenticationProvider)
                //添加自定义的Jwt认证过滤器，并放在UsernamePasswordAuthenticationFilter之前
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();



    }
}
