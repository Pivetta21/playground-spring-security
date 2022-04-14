package com.example.demo.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;
import java.util.List;

@Getter
@RequiredArgsConstructor
public class ApiExceptionDTO {

    private final String message;
    private final HttpStatus httpStatus;
    private final ZonedDateTime timestamp;
    private final List<FieldErrorDTO> errors;

}
