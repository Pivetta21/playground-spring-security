package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.payload.response.UserResponse;
import com.example.demo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    ResponseEntity<UserResponse> me() {
        User authenticatedUser = userService.findAuthenticatedUser();
        return ResponseEntity.ok(new UserResponse(authenticatedUser));
    }

    @GetMapping("/{uuid}")
    ResponseEntity<UserResponse> userByUuid(@PathVariable String uuid) {
        User user = userService.findUserByUUID(UUID.fromString(uuid));
        return ResponseEntity.ok(new UserResponse(user));
    }

}
