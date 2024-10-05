package com.christian.springsecurity.app.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    private final String privateKey;
    private final String userGenerator;

    public JwtUtils(@Value("${security.jwt.key.private}") String privateKey, @Value("${security.jwt.user.generator}") String userGenerator) {
        this.privateKey = privateKey;
        this.userGenerator = userGenerator;
    }

    public String createToken(Authentication authentication){
        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

        String username = authentication.getPrincipal().toString();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return JWT.create()
                .withIssuer(this.userGenerator) // USUARIO QUE GENERO EL TOKEN
                .withSubject(username)          // SUJETO, COMO EL username, A QUIEN SE LE VA A GENERAR EL TOKEN
                .withClaim("authorities", authorities) // AGREGANDO UN NUEVO PAR DE CLAVE-VALOR AL PAYLOAD
                .withIssuedAt(new Date())       // FECHA ACTUAL EN LA QUE SE GENERA EL TOKEN
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000)) // FECHA DE EXPIRACION DEL TOKEN = FECHA ACTUAL + 1800000 MILISEGUNDOS (30 MINUTOS)
                .withJWTId(UUID.randomUUID().toString())    // ESTABLECEMOS UN ID (IDENTIFICADOR) AL TOKEN BASADO EN UUID
                .withNotBefore(new Date(System.currentTimeMillis())) // A PARTIR DE QUE MOMENTO ESTE TOKEN SERA VALIDO, PUDIENDO AGREGARLE UN TIEMPO ADICIONAL, SI SE DESEA
                .sign(algorithm);
    }

    public DecodedJWT validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();

            // RETORNA EL TOKEN DECODIFICADO
            return verifier.verify(token);
        } catch(JWTVerificationException exception) {
            throw new JWTVerificationException("Invalid token, not Authorized");
        }
    }

    public String extractUsername(DecodedJWT decodedJWT){
        return decodedJWT.getSubject();
    }

    public Claim getEspecificClaim(DecodedJWT decodedJWT, String nameClaim){
        return decodedJWT.getClaim(nameClaim);
    }

    public Map<String, Claim> getAllClaims(DecodedJWT decodedJWT){
        return decodedJWT.getClaims();
    }
}
