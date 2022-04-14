package com.example.demo.service;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.model.RefreshToken;
import com.example.demo.model.User;
import com.example.demo.payload.response.JwtResponse;
import com.example.demo.repository.RefreshTokenRepository;
import com.example.demo.security.model.UserDetailsImpl;
import com.example.demo.security.util.CookieUtil;
import com.example.demo.security.util.JwtUtil;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final AuthenticationManager authenticationProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final CookieUtil cookieUtil;

    public AuthService(AuthenticationManager authenticationProvider, RefreshTokenRepository refreshTokenRepository, JwtUtil jwtUtil, CookieUtil cookieUtil) {
        this.authenticationProvider = authenticationProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
        this.cookieUtil = cookieUtil;
    }

    public ResponseEntity<JwtResponse> login(String email, String password, String accessToken, String refreshToken) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationProvider.authenticate(authenticationToken);
        User user = ((UserDetailsImpl) authentication.getPrincipal()).getUser();

        // Only works in a stateful environment
        // The security context will be cleared on the end of a request (i.e, SessionCreationPolicy.STATELESS)
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                user.getUuid(), null, user.getRole().getName().getGrantedAuthorities()
        ));

        HttpHeaders httpHeaders = new HttpHeaders();

        DecodedJWT accessTokenJWT = accessToken == null ? null : jwtUtil.decodeJWT(accessToken);
        DecodedJWT refreshTokenJWT = refreshToken == null ? null : jwtUtil.decodeJWT(refreshToken);

        String newRefreshToken = null;
        String newAccessToken = null;

        if (accessTokenJWT == null && refreshTokenJWT == null) {
            newAccessToken = jwtUtil.createAccessToken(user);
            createAccessTokenCookie(httpHeaders, newAccessToken);

            newRefreshToken = jwtUtil.createRefreshToken(user);
            createRefreshTokenCookie(httpHeaders, newRefreshToken);
        }

        if (accessTokenJWT == null && refreshTokenJWT != null) {
            newAccessToken = jwtUtil.createAccessToken(user);
            createAccessTokenCookie(httpHeaders, newAccessToken);

            newRefreshToken = refreshTokenJWT.getToken();
        }

        if (accessTokenJWT != null && refreshTokenJWT == null) {
            newAccessToken = accessTokenJWT.getToken();

            newRefreshToken = jwtUtil.createRefreshToken(user);
            createRefreshTokenCookie(httpHeaders, newRefreshToken);
        }

        if (accessTokenJWT != null && refreshTokenJWT != null) {
            newAccessToken = accessTokenJWT.getToken();
            newRefreshToken = refreshTokenJWT.getToken();
        }

        Optional<RefreshToken> rtOptional = refreshTokenRepository.findByUser(user);

        RefreshToken refreshTokenEntity;
        if (rtOptional.isPresent()) {
            refreshTokenEntity = rtOptional.get();
            refreshTokenEntity.setRefreshToken(newRefreshToken);
        } else {
            refreshTokenEntity = RefreshToken.builder().refreshToken(newRefreshToken).user(user).build();
        }
        refreshTokenRepository.save(refreshTokenEntity);

        return ResponseEntity.ok().headers(httpHeaders).body(new JwtResponse(newAccessToken, newRefreshToken));
    }

    public RefreshToken getRefreshTokenByUser(User user) {
        return refreshTokenRepository.findByUser(user).orElse(null);
    }

    public void updateRefreshToken(RefreshToken refreshToken) {
        refreshTokenRepository.save(refreshToken);
    }

    public void createAccessTokenCookie(HttpHeaders httpHeaders, String token) {
        HttpCookie accessTokenCookie = cookieUtil.createAccessTokenCookie(token, jwtUtil.getAccessTokenExpiration());
        httpHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
    }

    public void createRefreshTokenCookie(HttpHeaders httpHeaders, String token) {
        HttpCookie refreshTokenCookie = cookieUtil.createRefreshTokenCookie(token, jwtUtil.getRefreshTokenExpiration());
        httpHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
    }

}
