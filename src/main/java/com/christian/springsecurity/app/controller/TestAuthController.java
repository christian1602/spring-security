package com.christian.springsecurity.app.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

// DEBIDO A QUE TENEMOS @EnableMethodSecurity EN SecurityConfig
// PODEMOS USAR @PreAuthorize()
// DONDE denyAll() NOS INDICA QUE POR DEFECTO DENEGAMOS TODOS LOS ACCESOS A LA CLASE
// OBTENIENDO UNA RESPUESTA 403 (FORBIDDEN)
@RestController
@RequestMapping("/method")
// @PreAuthorize("denyAll()")
public class TestAuthController {

    @GetMapping("/get")
    // @PreAuthorize("hasAuthority('READ')")
    public String helloGet(){
        return "Hello World - GET";
    }

    @PostMapping("/post")
    // @PreAuthorize("hasAuthority('CREATE')")
    public String helloPost(){
        return "Hello World - POST";
    }

    @PutMapping("/put")
    public String helloPut(){
        return "Hello World - PUT";
    }

    @DeleteMapping("/delete")
    public String helloDelete(){
        return "Hello World - DELETE";
    }

    @PatchMapping("/patch")
    // @PreAuthorize("hasAuthority('REFACTOR')")
    public String helloPatch(){
        return "Hello World - PATCH";
    }
}
