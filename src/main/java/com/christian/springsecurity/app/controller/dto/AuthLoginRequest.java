package com.christian.springsecurity.app.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record AuthLoginRequest(
        @NotBlank String username,
        @NotBlank String password
){}
