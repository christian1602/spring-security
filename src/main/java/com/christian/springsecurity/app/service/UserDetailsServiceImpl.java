package com.christian.springsecurity.app.service;

import com.christian.springsecurity.app.persistence.entity.UserEntity;
import com.christian.springsecurity.app.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntityFound = this.userRepository.findUserEntityByUsername(username)
                .orElseThrow( () -> new UsernameNotFoundException("El usuario " + username + " no existe"));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        // EN SPRING SECURITY ES NECESARIO AGREGAR EL PREFIJO "ROLE_" PARA QUE UN ROL SEA RECONOCIDO COMO TAL
        authorityList.addAll(userEntityFound.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name())))
                .toList());

        // EN SPRING SECURITY NO ES NECESARIO AGREGAR NINGUN PREFIJO PARA QUE UN PERMISO SEA RECONOCIDO COMO TAL
        authorityList.addAll(userEntityFound.getRoles()
                .stream()
                .flatMap(role -> role.getPermissions()
                        .stream()
                        .map(permission -> new SimpleGrantedAuthority(permission.getName())))
                .toList());

        return new User(
                userEntityFound.getUsername(),
                userEntityFound.getPassword(),
                userEntityFound.isEnabled(),
                userEntityFound.isAccountNoExpired(),
                userEntityFound.isCredentialNoExpired(),
                userEntityFound.isAccountNoLocked(),
                authorityList);
    }
}
