package com.christian.springsecurity.app;

import com.christian.springsecurity.app.persistence.entity.PermissionEntity;
import com.christian.springsecurity.app.persistence.entity.RoleEntity;
import com.christian.springsecurity.app.persistence.entity.RoleEnum;
import com.christian.springsecurity.app.persistence.entity.UserEntity;
import com.christian.springsecurity.app.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurirtyAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurirtyAppApplication.class, args);
	}

	@Bean
	public CommandLineRunner init(UserRepository userRepository){
		return args -> {
			// CREATE PERMISSIONS
			PermissionEntity createPermission = PermissionEntity.builder().name("CREATE").build();
			PermissionEntity readPermission = PermissionEntity.builder().name("READ").build();
			PermissionEntity updatePermission = PermissionEntity.builder().name("UPDATE").build();
			PermissionEntity deletePermission = PermissionEntity.builder().name("DELETE").build();
			PermissionEntity refactorPermission = PermissionEntity.builder().name("REFACTOR").build();

			// CREATE ROLES
			RoleEntity adminRole = RoleEntity.builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissions(Set.of(createPermission,readPermission,updatePermission,deletePermission))
					.build();

			RoleEntity userRole = RoleEntity.builder()
					.roleEnum(RoleEnum.USER)
					.permissions(Set.of(createPermission,readPermission))
					.build();

			RoleEntity guestRole = RoleEntity.builder()
					.roleEnum(RoleEnum.GUEST)
					.permissions(Set.of(readPermission))
					.build();

			RoleEntity developerRole = RoleEntity.builder()
					.roleEnum(RoleEnum.DEVELOPER)
					.permissions(Set.of(createPermission,readPermission,updatePermission,deletePermission,refactorPermission))
					.build();

			// CREATE USERS
			UserEntity christianUser = UserEntity.builder()
					.username("christian")
					.password("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(adminRole))
					.build();

			UserEntity walterUser = UserEntity.builder()
					.username("walter")
					.password("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(userRole))
					.build();

			UserEntity lizUser = UserEntity.builder()
					.username("liz")
					.password("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(guestRole))
					.build();

			UserEntity bellaUser = UserEntity.builder()
					.username("bella")
					.password("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialNoExpired(true)
					.roles(Set.of(developerRole))
					.build();

			userRepository.saveAll(List.of(christianUser,walterUser,lizUser,bellaUser));
		};
	}
}
