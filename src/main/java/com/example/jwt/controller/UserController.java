package com.example.jwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(this.userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refreshToken = authorizationHeader.substring("Bearer ".length()); // On recupère notre JWT.
                Algorithm algo = Algorithm.HMAC256("secret".getBytes()); // On réinstancie l'algo qui permettra cette fois de le décoder.
                JWTVerifier verifier = JWT.require(algo).build();
                DecodedJWT decodedJWT = verifier.verify(refreshToken); // On décode notre JWT.
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);
                String accessToken = JWT.create()
                        .withSubject(user.getUsername()) // Unique identificateur, ici on choisit le Username
                        .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000)) // On set ici une date d'expiration.
                        .withIssuer(request.getRequestURI().toString()) // Créateur du token, ici je prends la request uri
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList())) // La liste des droits propres à l'utilisateur.
                        .sign(algo); // L'algorithme de signature, qui va sécuriser et rendre unique notre token.
                Map<String, String> mapTokens = new HashMap<>();
                mapTokens.put("access_token", accessToken);
                mapTokens.put("refresh_token", refreshToken);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), mapTokens); // On met nos tokens dans une map, que l'on retournera en responseBody si l'authent s'est bien passée.
            } catch (Exception e) {
                log.error("Error logging in {}", e.getMessage());
                response.setHeader("error", e.getMessage());
                Map<String, String> errors = new HashMap<>();
                errors.put("error_message", e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), errors);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }

}
@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}
