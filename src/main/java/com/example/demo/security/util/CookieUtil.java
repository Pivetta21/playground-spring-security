package com.example.demo.security.util;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class CookieUtil {

    public static final String ACCESS_TOKEN = "accessToken";
    public static final String REFRESH_TOKEN = "refreshToken";

    public HttpCookie createAccessTokenCookie(String token, Long duration) {
        String encryptedToken = SecurityCipherUtil.encrypt(token);
        return ResponseCookie.from(ACCESS_TOKEN, encryptedToken)
                .maxAge(TimeUnit.MINUTES.toSeconds(duration))
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie createRefreshTokenCookie(String token, Long duration) {
        String encryptedToken = SecurityCipherUtil.encrypt(token);
        return ResponseCookie.from(REFRESH_TOKEN, encryptedToken)
                .maxAge(TimeUnit.MINUTES.toSeconds(duration))
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie deleteAccessTokenCookie() {
        return ResponseCookie.from(ACCESS_TOKEN, "")
                .maxAge(0)
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from(REFRESH_TOKEN, "")
                .maxAge(0)
                .httpOnly(true)
                .path("/")
                .build();
    }

}
