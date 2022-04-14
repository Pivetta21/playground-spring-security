package com.example.demo.payload.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class RefreshJwtRequest {

    @NotBlank
    private final String accessToken;

    @NotBlank
    private final String refreshToken;

}
