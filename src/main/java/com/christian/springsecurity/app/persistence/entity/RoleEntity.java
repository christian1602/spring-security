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
@Table(name = "roles")
public class RoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // SE ESTABLECE QUE LA COLUMNA role_name ES DE TIPO STRING EN LA BASE DE DATOS
    // SPRING SE ENCARGA DE MAPEAR EL ENUMERADO A STRING EN LA BASE DE DATOS
    @Enumerated(EnumType.STRING)
    @Column(name = "role_name")
    private RoleEnum roleEnum;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "role_permission", joinColumns = @JoinColumn(name = "role_id"), inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<PermissionEntity> permissions = new HashSet<>();
}
