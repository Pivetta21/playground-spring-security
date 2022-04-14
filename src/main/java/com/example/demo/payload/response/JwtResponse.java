package com.example.demo.payload.response;

import lombok.Data;

@Data
public class JwtResponse {

    private final String accessToken;
    private final String refreshToken;

}
