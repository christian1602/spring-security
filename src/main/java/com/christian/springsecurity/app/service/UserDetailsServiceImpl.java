package com.christian.springsecurity.app.service;

import com.christian.springsecurity.app.controller.dto.AuthCreateUserRequest;
import com.christian.springsecurity.app.controller.dto.AuthLoginRequest;
import com.christian.springsecurity.app.controller.dto.AuthResponse;
import com.christian.springsecurity.app.persistence.entity.RoleEntity;
import com.christian.springsecurity.app.persistence.entity.UserEntity;
import com.christian.springsecurity.app.repository.RoleRepository;
import com.christian.springsecurity.app.repository.UserRepository;
import com.christian.springsecurity.app.util.JwtUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    public UserDetailsServiceImpl(
            UserRepository userRepository,
            RoleRepository roleRepository,
            JwtUtils jwtUtils,
            PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntityFound = this.userRepository.findUserEntityByUsername(username)
                .orElseThrow( () -> new UsernameNotFoundException("El usuario " + username + " no existe"));

        List<SimpleGrantedAuthority> authorityList = this.convertRolesToSimpleGrantedAuthorityList(userEntityFound.getRoles());

        return new User(
                userEntityFound.getUsername(),
                userEntityFound.getPassword(),
                userEntityFound.isEnabled(),
                userEntityFound.isAccountNoExpired(),
                userEntityFound.isCredentialNoExpired(),
                userEntityFound.isAccountNoLocked(),
                authorityList);
    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest){
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username,password);
        // DEBIDO A QUE EN EL LOGIN TODAVIA NO EXISTE EL TOKEN,
        // EL FILTRO DE TOKEN NO SE CONSIDERA Y CONTINUA CON EL SIGUIENTE FILTRO
        // ENTONCES DEBEMOS USAR setAuthentication(authentication) PARA ESTABLECER LA NUEVA AUTENTICACION
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = this.jwtUtils.createToken(authentication);
        return new AuthResponse(username,"User loged successfuly",accessToken,true);
    }

    private Authentication authenticate(String username, String password){
        UserDetails userDetails = this.loadUserByUsername(username);

        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username");
        }

        if (!passwordEncoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(username,userDetails.getPassword(),userDetails.getAuthorities());
    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest){
        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();
        List<String> roleRequest = authCreateUserRequest.authCreateRoleRequest().roleListName();

        Set<RoleEntity> roleEntitySet = new HashSet<>(this.roleRepository.findRoleEntityByRoleEnumIn(roleRequest));

        if (roleEntitySet.isEmpty()) {
            throw new IllegalArgumentException("The roles specified does not exist");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(this.passwordEncoder.encode(password))
                .isEnabled(true)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialNoExpired(true)
                .roles(roleEntitySet)
                .build();

        UserEntity userCreated = this.userRepository.save(userEntity);
        List<SimpleGrantedAuthority> authorityList = this.convertRolesToSimpleGrantedAuthorityList(userCreated.getRoles());

        Authentication authentication = new UsernamePasswordAuthenticationToken(userCreated.getUsername(),userCreated.getPassword(),authorityList);

        String accessToken = this.jwtUtils.createToken(authentication);
        return new AuthResponse(userCreated.getUsername(),"User created successfuly",accessToken,true);
    }

    private List<SimpleGrantedAuthority> convertRolesToSimpleGrantedAuthorityList(Set<RoleEntity> roles){
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        // EN SPRING SECURITY ES NECESARIO AGREGAR EL PREFIJO "ROLE_" PARA QUE UN ROL SEA RECONOCIDO COMO TAL
        authorityList.addAll(roles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())))
                .toList());

        // EN SPRING SECURITY NO ES NECESARIO AGREGAR NINGUN PREFIJO PARA QUE UN PERMISO SEA RECONOCIDO COMO TAL
        authorityList.addAll(roles
                .stream()
                .flatMap(role -> role.getPermissions()
                        .stream()
                        .map(permission -> new SimpleGrantedAuthority(permission.getName())))
                .toList());

        return authorityList;
    }
}
