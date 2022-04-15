package com.example.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    String admin() {
        return "Hello Admin!";
    }

    @PreAuthorize("hasRole('ROLE_STAFF')")
    @GetMapping("/staff")
    String staff() {
        return "Hello Staff!";
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    String user() {
        return "Hello User!";
    }

    @GetMapping("/test")
    String test() {
        return "Hello Spring Security!";
    }

}
