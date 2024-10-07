package com.christian.springsecurity.app.repository;

import com.christian.springsecurity.app.persistence.entity.RoleEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends CrudRepository<RoleEntity, Long> {

    // El metodo findRoleEntityByRoleEnumIn genera una consulta SQL que busca
    // todas las entidades RoleEntity cuyos valores en el campo roleEnum coinciden con cualquiera de los valores en la lista rolesName¿
    // SQL generado:
    // SELECT * FROM role_entity WHERE role_enum IN (?, ?, ..., ?);
    List<RoleEntity> findRoleEntityByRoleEnumIn(List<String> rolesName);
}
