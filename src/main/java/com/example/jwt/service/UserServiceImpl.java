package com.example.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User has been found in the database");
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} in the database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepository.findAll();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refreshToken = authorizationHeader.substring("Bearer ".length()); // On recupère notre JWT.
                Algorithm algo = Algorithm.HMAC256("secret".getBytes()); // On réinstancie l'algo qui permettra cette fois de le décoder.
                JWTVerifier verifier = JWT.require(algo).build();
                DecodedJWT decodedJWT = verifier.verify(refreshToken); // On décode notre JWT.
                String username = decodedJWT.getSubject();
                User user = this.getUser(username);
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
