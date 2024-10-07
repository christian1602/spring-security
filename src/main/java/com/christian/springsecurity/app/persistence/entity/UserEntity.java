package com.christian.springsecurity.app.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;
    private String password;

    @Column(name = "is_enabled")
    private boolean isEnabled; // REQUERIDO POR SPRING SECURITY

    @Column(name = "account_no_expired")
    private boolean accountNoExpired; // REQUERIDO POR SPRING SECURITY

    @Column(name = "account_no_locked")
    private boolean accountNoLocked; // REQUERIDO POR SPRING SECURITY

    @Column(name = "credential_no_expired")
    private boolean credentialNoExpired; // REQUERIDO POR SPRING SECURITY

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles = new HashSet<>();
}
