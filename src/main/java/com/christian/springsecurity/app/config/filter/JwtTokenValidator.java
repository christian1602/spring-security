package com.christian.springsecurity.app.config.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.christian.springsecurity.app.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;

public class JwtTokenValidator extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // EXTRAER EL TOKEN JWT DE LA CABECERA: Authorization
        String jwtToken = this.extractToken(request);

        if (jwtToken != null){
            // INTENTAR OBTENER LA AUTENTICACION A PARTIR DEL TOKEN JWT
            Authentication authentication = this.getAuthentication(jwtToken);

            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Invalid token, not Authorized at doFilterInternal");
                return; // SALIR DEL FILTRO SI EL TOKEN NO ES VALIDO
            }
        }

        // CONTINUAR CON EL SIGUIENTE FILTRO
        // filterChain MANEJA LA SECUENCIA DE FILTROS
        filterChain.doFilter(request,response);
    }

    private Authentication getAuthentication(String jwtToken){
        // VALIDAR EL TOKEN Y CAPTURAR EXCEPCIONES
        DecodedJWT decodedJWT;

        try {
            decodedJWT = this.jwtUtils.validateToken(jwtToken);
        } catch(Exception e){
            return null;
        }

        // GENERAMOS Y RETORNAMOS EL Authentication
        String username = this.jwtUtils.extractUsername(decodedJWT);
        String stringAuthorities = this.jwtUtils.getEspecificClaim(decodedJWT,"authorities").asString();
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities);

        return new UsernamePasswordAuthenticationToken(username,null,authorities);
    }

    private String extractToken(HttpServletRequest request){
        // EJEMPLO: Authorization: bearer VALOR_DE_MI_TOKEN
        return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                .filter(header -> header.startsWith(BEARER_PREFIX))
                .map(header -> header.substring(BEARER_PREFIX.length()))
                .orElse(null);
    }
}
