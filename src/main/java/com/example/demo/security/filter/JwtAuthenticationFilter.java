package com.example.demo.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.security.model.RoleEnum;
import com.example.demo.security.util.JwtUtil;
import com.example.demo.security.util.SecurityCipherUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.UUID;


public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final List<AntPathRequestMatcher> IGNORE_REQUEST_PATH_LIST = List.of(
            new AntPathRequestMatcher("/login", "POST"),
            new AntPathRequestMatcher("/signup", "POST"),
            new AntPathRequestMatcher("/refresh", "POST")
    );

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (IGNORE_REQUEST_PATH_LIST.stream().noneMatch(path -> path.matches(request))) {
            try {
                UsernamePasswordAuthenticationToken authentication = this.convertRequest(request, true);
                if (authentication != null) SecurityContextHolder.getContext().setAuthentication(authentication);

                filterChain.doFilter(request, response);
            } catch (Exception ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getLocalizedMessage());
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private UsernamePasswordAuthenticationToken convertRequest(HttpServletRequest request, boolean fromCookie) {
        if (fromCookie) return this.convertCookies(request);
        return this.convertHeader(request);
    }

    private UsernamePasswordAuthenticationToken convertHeader(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) return null;

        header = header.trim();
        if (!StringUtils.startsWithIgnoreCase(header, JwtUtil.BEARER_PREFIX)) {
            return null;
        } else if (header.equalsIgnoreCase(JwtUtil.BEARER_PREFIX)) {
            throw new BadCredentialsException("Empty bearer authentication token");
        } else {
            String token = header.replace(JwtUtil.BEARER_PREFIX, "");
            return getUsernamePasswordAuthenticationToken(token);
        }
    }

    private UsernamePasswordAuthenticationToken convertCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        String token = null;
        for (Cookie cookie : cookies) {
            if ("accessToken".equals(cookie.getName())) {
                String accessToken = cookie.getValue();
                if (accessToken == null) return null;

                token = SecurityCipherUtil.decrypt(accessToken);
            }
        }

        if (StringUtils.hasText(token)) return getUsernamePasswordAuthenticationToken(token);
        return null;
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String token) {
        DecodedJWT decodedJWT = jwtUtil.decodeJWT(token);
        if (decodedJWT == null) throw new BadCredentialsException("Invalid jwt authentication token");

        try {
            String subject = decodedJWT.getSubject();
            String role = decodedJWT.getClaim(JwtUtil.ROLE_CLAIM).asString();

            return new UsernamePasswordAuthenticationToken(
                    UUID.fromString(subject),
                    null,
                    RoleEnum.valueOf(role).getGrantedAuthorities()
            );
        } catch (Exception ex) {
            return null;
        }
    }

}
