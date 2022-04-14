package com.example.demo.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(value = {ApiException.class})
    public ResponseEntity<Object> handleApiException(ApiException ex) {
        return exceptionResponse(ex.getMessage(), ex.getHttpStatus(), Collections.emptyList());
    }

    @ExceptionHandler(value = {MethodArgumentNotValidException.class})
    public ResponseEntity<Object> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        List<FieldErrorDTO> errors = new ArrayList<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.add(new FieldErrorDTO(error.getField(), error.getDefaultMessage()));
        }

        return exceptionResponse("Error while validating the request body", HttpStatus.BAD_REQUEST, errors);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Object> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
        return exceptionResponse(ex.getLocalizedMessage(), HttpStatus.METHOD_NOT_ALLOWED, Collections.emptyList());
    }

    private ResponseEntity<Object> exceptionResponse(String message, HttpStatus httpStatus, List<FieldErrorDTO> errors) {
        return new ResponseEntity<>(
                new ApiExceptionDTO(message, httpStatus, ZonedDateTime.now(ZoneId.of("Z")), errors),
                httpStatus
        );
    }

}
