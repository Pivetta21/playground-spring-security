package com.example.demo.payload.request;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Data
public class LoginRequest {

    @Email
    @NotBlank
    private final String email;

    @Size(min = 6, max = 40)
    @NotBlank
    private final String password;

}
