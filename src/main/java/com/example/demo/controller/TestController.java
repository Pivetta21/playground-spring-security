package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/admin")
    String admin() {
        return "Hello Admin!";
    }

    @GetMapping("/staff")
    String staff() {
        return "Hello Staff!";
    }

    @GetMapping("/user")
    String user() {
        return "Hello User!";
    }

    @GetMapping("/test")
    String test() {
        return "Hello Spring Security!";
    }

}
