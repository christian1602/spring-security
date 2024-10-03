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
			PermissionEntity createPermission = new PermissionEntity();
			createPermission.setName("CREATE");

			PermissionEntity readPermission = new PermissionEntity();
			readPermission.setName("READ");

			PermissionEntity updatePermission = new PermissionEntity();
			updatePermission.setName("UPDATE");

			PermissionEntity deletePermission = new PermissionEntity();
			deletePermission.setName("DELETE");

			PermissionEntity refactorPermission = new PermissionEntity();
			refactorPermission.setName("REFACTOR");

			// CREATE ROLES
			RoleEntity adminRole = new RoleEntity();
			adminRole.setRoleEnum(RoleEnum.ADMIN);
			adminRole.setPermissions(Set.of(createPermission,readPermission,updatePermission,deletePermission));

			RoleEntity userRole = new RoleEntity();
			userRole.setRoleEnum(RoleEnum.USER);
			userRole.setPermissions(Set.of(createPermission,readPermission));

			RoleEntity guestRole = new RoleEntity();
			guestRole.setRoleEnum(RoleEnum.GUEST);
			guestRole.setPermissions(Set.of(readPermission));

			RoleEntity developerRole = new RoleEntity();
			developerRole.setRoleEnum(RoleEnum.DEVELOPER);
			developerRole.setPermissions(Set.of(createPermission,readPermission,updatePermission,deletePermission,refactorPermission));

			// CREATE USERS
			UserEntity christianUser = new UserEntity();
			christianUser.setUsername("christian");
			christianUser.setPassword("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi");
			christianUser.setEnabled(true);
			christianUser.setAccountNoExpired(true);
			christianUser.setAccountNoLocked(true);
			christianUser.setCredentialNoExpired(true);
			christianUser.setRoles(Set.of(adminRole));

			UserEntity walterUser = new UserEntity();
			walterUser.setUsername("walter");
			walterUser.setPassword("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi");
			walterUser.setEnabled(true);
			walterUser.setAccountNoExpired(true);
			walterUser.setAccountNoLocked(true);
			walterUser.setCredentialNoExpired(true);
			walterUser.setRoles(Set.of(userRole));

			UserEntity lizUser = new UserEntity();
			lizUser.setUsername("liz");
			lizUser.setPassword("12$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi3456");
			lizUser.setEnabled(true);
			lizUser.setAccountNoExpired(true);
			lizUser.setAccountNoLocked(true);
			lizUser.setCredentialNoExpired(true);
			lizUser.setRoles(Set.of(guestRole));

			UserEntity bellaUser = new UserEntity();
			bellaUser.setUsername("bella");
			bellaUser.setPassword("$2a$10$qG3wS1Evr6WNJIJof5TEXOV5CTIJZDrenVSSxqJ2kIWbq6HDydVNi");
			bellaUser.setEnabled(true);
			bellaUser.setAccountNoExpired(true);
			bellaUser.setAccountNoLocked(true);
			bellaUser.setCredentialNoExpired(true);
			bellaUser.setRoles(Set.of(developerRole));

			userRepository.saveAll(List.of(christianUser,walterUser,lizUser,bellaUser));
		};
	}
}
