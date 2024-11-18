package com.example.security.config;


import com.example.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository userRepository;
   @Bean
   public UserDetailsService userDetailsService (){

//       return username -> userRepository.findByEmail(username)
//               .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));
       return username -> {
           System.out.println("Loading user by username: " + username); // 打印请求的用户名
           return userRepository.findByEmail(username)
                   .orElseThrow(() -> {
                       System.out.println("User not found in database for username: " + username);
                       return new UsernameNotFoundException("User not found with email: " + username);
                   });
       };
   }
   // 身份验证提供者,使用 UserDetailsService 加载用户信息，并用 PasswordEncoder 验证用户的密码
   @Bean
    public AuthenticationProvider authenticationProvider(){
       // SpringSecurity内置的身份验证提供者
       DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
       authProvider.setUserDetailsService(userDetailsService());
       authProvider.setPasswordEncoder(passwordEncoder());
       return authProvider;
   }
   //身份验证管理者,管理和协调多个 AuthenticationProvider 的身份验证过程。
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
    }
    //负责对密码进行加密和验证匹配。
   @Bean
    public PasswordEncoder passwordEncoder(){
       return new BCryptPasswordEncoder();
   }
}
