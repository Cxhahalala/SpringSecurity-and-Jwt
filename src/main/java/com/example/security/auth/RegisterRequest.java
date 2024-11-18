package com.example.security.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Data
@AllArgsConstructor
@NonNull
@Builder
public class RegisterRequest {
    private String firstname;

    private String lastname;

    private String email;

    private String password;
}
