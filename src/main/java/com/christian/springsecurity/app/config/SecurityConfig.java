package com.christian.springsecurity.app.config;

import com.christian.springsecurity.app.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // PASO 1: CONFIGURANDO SECURITY FILTER CHAIN SIN ANOTACIONES EN EL CONTROLADOR TestAuthController
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 1.1. EN API REST, EL csrf NO ES USADO. EN FORMULARIOS WEB, EL csrf SI ES USADO.
        // 1.2. httpBasic USADO CUANDO NOS VAMOS A LOGEAR CON USERNAME Y PASSWORD
        //      Customizer.withDefaults() USADO CUANDO LA AUTENTICACION BASICA VA A FUNCIONAR POR DEFECTO
        //      ENTIENDASE CON POR DEFECTO, QUE VA A FUNCIONAR CON USERNAME Y PASSWORD
        // 1.3. LOS API REST NO MANEJAN SESIONES, SON SIN ESTADO. LOS PROYECTOS WEB, SI USAN SESIONES, SON CON ESTADO.
        // POSIBLES RESPUESTAS
        // CREDENCIALES VALIDAS Y ROLES VALIDOS, ENTONCES LA RESPUESTA ES 200 (OK)
        // CREDENCIALES NO VALIDAS Y ROLES VALIDOS, ENTONCES LA RESPUESTA ES 401 (UNAUTHORIZED)
        // CREDENCIALES VALIDAS Y ROLES NO VALIDOS, ENTONCES LA RESPUESTA ES 403 (FORBIDDEN)
        return httpSecurity
                // .csrf(csrf -> csrf.disable())  // 1.1
                .csrf(AbstractHttpConfigurer::disable)  // 1.1
                .httpBasic(Customizer.withDefaults()) // 1.2
                .sessionManagement(session ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 1.3
                .authorizeHttpRequests(auths -> {
                    // PRIMERO: CONFIGURAR LOS ENDPOINTS PUBLICOS
                    auths.requestMatchers(HttpMethod.GET, "/auth/get").permitAll();

                    // SEGUNDO: CONFIGURAR LOS ENDPOINTS PRIVADOS
                    // auths.requestMatchers(HttpMethod.POST, "/auth/post").hasAuthority("CREATE");
                    // auths.requestMatchers(HttpMethod.POST, "/auth/post").hasAnyAuthority("CREATE", "READ");
                    auths.requestMatchers(HttpMethod.PATCH, "/auth/patch").hasAnyAuthority("REFACTOR");

                    // auths.requestMatchers(HttpMethod.POST, "/auth/post").hasRole("ADMIN");
                    auths.requestMatchers(HttpMethod.POST, "/auth/post").hasAnyRole("ADMIN","DEVELOPER");

                    // TERCERO: CONFIGURAR EL RESTO DE ENDPOINTS - NO ESPECIFICADOS
                    // auths.anyRequest().authenticated(); // CREDENCIALES VALIDAS, ENTONCES LA RESPUESTA ES 200 (OK)
                    auths.anyRequest().denyAll();    // LA RESPUESTA SIEMPRE SERA 403 (FORBIDDEN)
                })
                .build();
    }

    // PASO 1: CONFIGURANDO SECURITY FILTER CHAIN CON ANOTACIONES EN EL CONTROLADOR TestAuthController
    /*@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 1.1. EN API REST, EL csrf NO ES USADO. EN FORMULARIOS WEB, EL csrf SI ES USADO.
        // 1.2. httpBasic USADO CUANDO NOS VAMOS A LOGEAR CON USERNAME Y PASSWORD
        //      Customizer.withDefaults() USADO CUANDO LA AUTENTICACION BASICA VA A FUNCIONAR POR DEFECTO
        //      ENTIENDASE CON POR DEFECTO, QUE VA A FUNCIONAR CON USERNAME Y PASSWORD
        // 1.3. LOS API REST NO MANEJAN SESIONES, SON SIN ESTADO. LOS PROYECTOS WEB, SI USAN SESIONES, SON CON ESTADO.
        // POSIBLES RESPUESTAS
        // CREDENCIALES VALIDAS Y ROLES VALIDOS, ENTONCES LA RESPUESTA ES 200 (OK)
        // CREDENCIALES NO VALIDAS Y ROLES VALIDOS, ENTONCES LA RESPUESTA ES 401 (UNAUTHORIZED)
        // CREDENCIALES VALIDAS Y ROLES NO VALIDOS, ENTONCES LA RESPUESTA ES 403 (FORBIDDEN)
        return httpSecurity
                // .csrf(csrf -> csrf.disable())  // 1.1
                .csrf(AbstractHttpConfigurer::disable)  // 1.1 // csrf -> csrf.disable() es reemplazaddo por AbstractHttpConfigurer::disable
                .httpBasic(Customizer.withDefaults()) // 1.2
                .sessionManagement(session ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 1.3
                .build();
    }*/

    // PASO 2: CONFIGURANDO AUTHENTICATION MANAGER
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // PASO 3: CONFIGURANDO UN PROVIDER EN PARTICULAR
    // EN ESTE CASO, USAREMOS DaoAuthenticationProvider, QUE NECESITA UN PasswordEncoder Y UN UserDetailsService
    // PASO 4: SE CONFIGURO EL UserDetailsService COMO UN SERVICIO CON LA CLASE UserDetailsServiceImpl
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsServiceImpl userDetailsService){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(this.passwordEncoder());
        provider.setUserDetailsService(userDetailsService);

        return provider;
    }

    // PASO 4: CONFIGURANDO EL UserDetailsService - SOLO PARA DATOS DE PRUEBA EN MEMORIA
    /*@Bean
    public UserDetailsService userDetailsService(){
        List<UserDetails> userDetailsList = new ArrayList<>();
        userDetailsList.add(User.withUsername("christian")
                .password("123456")
                .roles("ADMIN")
                .authorities("READ","CREATE")
                .build());

        userDetailsList.add(User.withUsername("walter")
                .password("123456")
                .roles("USER")
                .authorities("READ")
                .build());

        return new InMemoryUserDetailsManager(userDetailsList);
    }*/

    // PASO 5: CONFIGURANDO EL TIPO DE PasswordEncoder A UTILIZAR
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // ESTE METODO main, ES SOLO PARA OBTENER LA ENCRIPTACION DEL PASSWORD 123456
    // QUE ES: $2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi
    // public static void main(String[] args) {
    //    System.out.println(new BCryptPasswordEncoder().encode("123456"));
    //}
}
