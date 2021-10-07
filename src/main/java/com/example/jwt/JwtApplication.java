package com.example.jwt;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER")); // Utilisateur
			userService.saveRole(new Role(null, "ROLE_PRESTATAIRE")); // Prestataire externe
			userService.saveRole(new Role(null, "ROLE_MEDECIN")); // Medecin (pareil que presta, mais aura accès aux dossiers médicaux)
			userService.saveRole(new Role(null, "ROLE_ADMIN")); // Le mec d'AssurMob

			userService.saveUser(new User(null, "Adil_Testelin", "Adil", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "PA_LeBoss", "PA", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Tommy_FromBroucker", "LeGrincheux", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Raph_LeBarman", "Raph", "1234", new ArrayList<>()));

			userService.addRoleToUser("Adil", "ROLE_USER");
			userService.addRoleToUser("PA", "ROLE_PRESTATAIRE");
			userService.addRoleToUser("LeGrincheux", "ROLE_MEDECIN");
			userService.addRoleToUser("LeGrincheux", "ROLE_PRESTATAIRE");
			userService.addRoleToUser("Raph", "ROLE_ADMIN");
		};
	}

}
