package com.example.security.auth;

import com.example.security.config.JwtService;
import com.example.security.user.Role;
import com.example.security.user.User;
import com.example.security.user.UserRepository;

import lombok.RequiredArgsConstructor;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var encodedPassword = passwordEncoder.encode(request.getPassword());
        System.out.println("Encoded password: " + encodedPassword); // 打印加密后的密码
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(encodedPassword) //加密密码
                .role(Role.user)
                .build();
        System.out.println("Before save: " + user);
        userRepository.save(user);
        System.out.println("After save: " + user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        System.out.println("Authentication request: email=" + request.getEmail() + ", password=" + request.getPassword());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user=userRepository.findByEmail(request.getEmail())
                        .orElseThrow(() -> {
                            System.out.println("User not found for email: " + request.getEmail());
                            return new RuntimeException("User not found");});
        System.out.println("User found: " + user); // 打印从数据库中找到的用户信息
        System.out.println("Encoded password in database: " + user.getPassword()); // 打印数据库中加密的密码
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
