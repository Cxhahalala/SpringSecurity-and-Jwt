package com.example.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    // 注册
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(authenticationService.register(request));
    }
    // 身份验证
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        boolean isValid = passwordEncoder.matches("1234", "$2a$10$Rss2C3ozYLA2pf81tJzkDuZrO2eR0KAFs/e7klWXTj1QJzwAlXdHO");
        System.out.println(isValid); // 应返回 true
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
