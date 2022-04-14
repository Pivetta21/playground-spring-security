package com.example.demo.security;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class JwtConfigProperties {

    @Value("${demo.jwt.access_token_expiration}")
    private Long accessTokenExpiration;

    @Value("${demo.jwt.refresh_token_expiration}")
    private Long refreshTokenExpiration;

    @Value("${demo.jwt.sign_secret}")
    private String signSecret;

}
