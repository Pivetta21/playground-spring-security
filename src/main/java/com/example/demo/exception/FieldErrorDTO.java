package com.example.demo.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;
import java.util.List;

@Getter
@RequiredArgsConstructor
public class FieldErrorDTO {

    private final String field;
    private final String message;

}
