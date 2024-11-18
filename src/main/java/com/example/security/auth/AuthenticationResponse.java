package com.example.security.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Data
@AllArgsConstructor
@NonNull
@Builder
public class AuthenticationResponse {
    private String token;
}
