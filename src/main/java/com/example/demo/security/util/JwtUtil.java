package com.example.demo.security.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.model.User;
import com.example.demo.security.JwtConfigProperties;
import com.example.demo.security.model.PermissionEnum;
import com.example.demo.security.model.RoleEnum;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    public final static String ROLE_CLAIM = "role";
    public final static String PERMISSIONS_CLAIM = "permissions";
    public final static String BEARER_PREFIX = "Bearer ";

    private final JwtConfigProperties jwtProperties;
    private final Algorithm signAlgorithm;

    public JwtUtil(JwtConfigProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signAlgorithm = Algorithm.HMAC512(jwtProperties.getSignSecret());
    }

    public String createAccessToken(User user) {
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneId.of("Z"));
        Instant now = zonedDateTime.toInstant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plus(jwtProperties.getAccessTokenExpiration(), ChronoUnit.MINUTES);

        RoleEnum roleEnum = user.getRole().getName();
        return JWT.create()
                .withSubject(user.getUuid().toString())
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiration))
                .withClaim(ROLE_CLAIM, roleEnum.name())
                .withClaim(PERMISSIONS_CLAIM, roleEnum.getPermissions().stream().map(PermissionEnum::name).toList())
                .sign(signAlgorithm);
    }

    public String createRefreshToken(User user) {
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneId.of("Z"));
        Instant now = zonedDateTime.toInstant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plus(jwtProperties.getAccessTokenExpiration(), ChronoUnit.MINUTES);

        return JWT.create()
                .withSubject(user.getUuid().toString())
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiration))
                .sign(signAlgorithm);
    }

    public DecodedJWT decodeJWT(String token) {
        try {
            JWTVerifier verifier = JWT.require(signAlgorithm).build();
            return verifier.verify(token);
        } catch (JWTVerificationException ex) {
            return null;
        }
    }

    public UUID getSubjectFromToken(String token) {
        try {
            DecodedJWT decode = JWT.decode(token);
            String subject = decode.getSubject();
            return UUID.fromString(subject);
        } catch (JWTDecodeException | IllegalArgumentException ex) {
            return null;
        }
    }

    public Long getAccessTokenExpiration() {
        return jwtProperties.getAccessTokenExpiration();
    }

    public Long getRefreshTokenExpiration() {
        return jwtProperties.getRefreshTokenExpiration();
    }

}
