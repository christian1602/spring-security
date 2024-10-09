package com.christian.springsecurity.app.controller;

import com.christian.springsecurity.app.controller.dto.AuthCreateUserRequest;
import com.christian.springsecurity.app.controller.dto.AuthLoginRequest;
import com.christian.springsecurity.app.controller.dto.AuthResponse;
import com.christian.springsecurity.app.service.UserDetailsServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final UserDetailsServiceImpl userDetailsService;

    public AuthenticationController(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthCreateUserRequest authCreateUserRequest){
        try {
            AuthResponse response = this.userDetailsService.createUser(authCreateUserRequest);
            return new ResponseEntity<AuthResponse>(response, HttpStatus.CREATED);
        } catch(IllegalArgumentException ex){
            // Esta excepción se lanza si los roles no existen
            return new ResponseEntity<AuthResponse>(new AuthResponse(authCreateUserRequest.username(), ex.getMessage(), null, false), HttpStatus.BAD_REQUEST);
        } catch(Exception ex) {
            // Manejo de errores genéricos
            return new ResponseEntity<AuthResponse>(new AuthResponse(authCreateUserRequest.username(), "Error during registration", null, false), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/log-in")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthLoginRequest authLoginRequest){
        try {
            return new ResponseEntity<AuthResponse>(this.userDetailsService.loginUser(authLoginRequest), HttpStatus.OK);
        } catch(BadCredentialsException ex){
            // Manejo de errores: devolver 401 Unauthorized
            return new ResponseEntity<AuthResponse>(new AuthResponse(authLoginRequest.username(), ex.getMessage(), null, false), HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            // Manejo de errores genéricos
            return new ResponseEntity<AuthResponse>(new AuthResponse(authLoginRequest.username(), "Error during login", null, false), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
