package com.example.demo.controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.exception.ApiException;
import com.example.demo.model.RefreshToken;
import com.example.demo.model.User;
import com.example.demo.payload.request.LoginRequest;
import com.example.demo.payload.request.RefreshJwtRequest;
import com.example.demo.payload.request.SignUpRequest;
import com.example.demo.payload.response.JwtResponse;
import com.example.demo.payload.response.UserResponse;
import com.example.demo.security.util.JwtUtil;
import com.example.demo.security.util.SecurityCipherUtil;
import com.example.demo.service.AuthService;
import com.example.demo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.UUID;

@Slf4j
@RestController
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService, UserService userService, JwtUtil jwtUtil) {
        this.authService = authService;
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    ResponseEntity<UserResponse> signUp(@RequestBody @Valid SignUpRequest body, UriComponentsBuilder uriBuilder) {
        User user = userService.createUser(body.getEmail(), body.getPassword(), body.getNickname());
        URI uri = uriBuilder.path("/user/{uuid}").buildAndExpand(user.getUuid()).toUri();
        return ResponseEntity.created(uri).body(new UserResponse(user));
    }

    @PostMapping("/login")
    ResponseEntity<JwtResponse> login(
            @RequestBody @Valid LoginRequest body,
            @CookieValue(name = "accessToken", required = false) String accessToken,
            @CookieValue(name = "refreshToken", required = false) String refreshToken
    ) {
        String decryptedAccessToken = SecurityCipherUtil.decrypt(accessToken);
        String decryptedRefreshToken = SecurityCipherUtil.decrypt(refreshToken);
        return authService.login(body.getEmail(), body.getPassword(), decryptedAccessToken, decryptedRefreshToken);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(
            @CookieValue(name = "accessToken", required = false) String accessTokenCookie,
            @CookieValue(name = "refreshToken", required = false) String refreshTokenCookie
    ) {
        HttpHeaders httpHeaders = new HttpHeaders();

        String decryptedAccessToken = SecurityCipherUtil.decrypt(accessTokenCookie);
        String decryptedRefreshToken = SecurityCipherUtil.decrypt(refreshTokenCookie);

        String refreshToken = this.validateAndGetRefreshToken(decryptedRefreshToken);
        UUID accessTokenSubject = this.validateAccessTokenAndGetSubject(decryptedAccessToken);
        JwtResponse jwtResponse = this.getJwtResponse(accessTokenSubject, refreshToken, httpHeaders);

        return ResponseEntity.ok().headers(httpHeaders).body(jwtResponse);
    }

    @PostMapping("/refresh-header")
    ResponseEntity<JwtResponse> refreshAuth(@RequestBody @Valid RefreshJwtRequest body) {
        String refreshToken = validateAndGetRefreshToken(body.getRefreshToken());
        UUID accessTokenSubject = this.validateAccessTokenAndGetSubject(body.getAccessToken());
        JwtResponse jwtResponse = this.getJwtResponse(accessTokenSubject, refreshToken, null);

        return ResponseEntity.ok(jwtResponse);
    }

    private String validateAndGetRefreshToken(String refreshToken) {
        DecodedJWT refreshTokenDecoded = refreshToken == null ? null : jwtUtil.decodeJWT(refreshToken);
        if (refreshTokenDecoded == null) throw new ApiException("Refresh token is invalid", HttpStatus.UNAUTHORIZED);
        return refreshTokenDecoded.getToken();
    }

    private UUID validateAccessTokenAndGetSubject(String accessToken) {
        UUID accessTokenSubject = accessToken == null ? null : jwtUtil.getSubjectFromToken(accessToken);
        if (accessTokenSubject == null) throw new ApiException("Access token is invalid", HttpStatus.UNAUTHORIZED);
        return accessTokenSubject;
    }

    private JwtResponse getJwtResponse(UUID accessTokenSubject, String refreshToken, HttpHeaders httpHeaders) {
        UUID refreshTokenSubject = jwtUtil.getSubjectFromToken(refreshToken);
        if (!accessTokenSubject.equals(refreshTokenSubject)) {
            throw new ApiException("Invalid subjects", HttpStatus.UNAUTHORIZED);
        }

        User user = userService.findUserByUUID(accessTokenSubject);
        RefreshToken refreshTokenEntity = authService.getRefreshTokenByUser(user);

        if (!refreshTokenEntity.getRefreshToken().equals(refreshToken)) {
            throw new ApiException("Refresh tokens are not equal", HttpStatus.UNAUTHORIZED);
        }

        String newAccessToken = jwtUtil.createAccessToken(user);
        if (httpHeaders != null) authService.createAccessTokenCookie(httpHeaders, newAccessToken);

        String newRefreshToken = jwtUtil.createRefreshToken(user);
        if (httpHeaders != null) authService.createRefreshTokenCookie(httpHeaders, newRefreshToken);

        refreshTokenEntity.setRefreshToken(newRefreshToken);
        authService.updateRefreshToken(refreshTokenEntity);

        return new JwtResponse(newAccessToken, newRefreshToken);
    }

}
