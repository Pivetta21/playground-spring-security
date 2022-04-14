package com.example.demo.service;

import com.example.demo.exception.ApiException;
import com.example.demo.model.User;
import com.example.demo.repository.RoleRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.model.RoleEnum;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User createUser(String email, String password, String nickname) {
        userRepository.findByEmail(email).ifPresent(user -> {
            throw new ApiException(String.format("Email '%s' is already being used", user.getEmail()), HttpStatus.CONFLICT);
        });

        var studentRole = roleRepository.findByName(RoleEnum.USER).orElseThrow();
        var user = User.builder()
                .nickname(nickname)
                .email(email)
                .password(passwordEncoder.encode(password))
                .createdAt(ZonedDateTime.now())
                .uuid(UUID.randomUUID())
                .role(studentRole)
                .build();

        return userRepository.save(user);
    }

    public User findAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication.getPrincipal() instanceof UUID uuid) return findUserByUUID(uuid);
        throw new ApiException("No valid authentication token found", HttpStatus.UNAUTHORIZED);
    }

    public User findUserByUUID(UUID uuid) {
        return userRepository.findByUuid(uuid).orElseThrow(
                () -> new ApiException("User '" + uuid + "' not found", HttpStatus.NOT_FOUND)
        );
    }

}
