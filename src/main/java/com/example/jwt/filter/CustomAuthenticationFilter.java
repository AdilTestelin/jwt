package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@AllArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override // Quand l'user tente de se login // Si l'authentification n'est pas successfull, Spring va lancer une erreur
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password"); // On récup l'username et le password de notre request.
        log.info("Username is {}", username);
        log.info("Password is {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password); // On créé un authentication token à partir de ces crédentials.
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override // Send the access token and the refreshtoken if the authentication is successfull
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal(); // Retourne le user qui a été authentifié.
        Algorithm algo = Algorithm.HMAC256("secret".getBytes()); // Ici utiliser une variable d'environnement : cette ligne nous permet de générer un algorithme d'encryptage
        String accessToken = JWT.create()
                .withSubject(user.getUsername()) // Unique identificateur, ici on choisit le Username
                .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000)) // On set ici une date d'expiration.
                .withIssuer(request.getRequestURI().toString()) // Créateur du token, ici je prends la request uri
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())) // La liste des droits propres à l'utilisateur.
                .sign(algo); // L'algorithme de signature, qui va sécuriser et rendre unique notre token.

        // Maintenant, on créé notre refreshToken :
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 300 * 60 * 1000))
                .withIssuer(request.getRequestURI().toString())
                .sign(algo);


        Map<String, String> mapTokens = new HashMap<>();
        mapTokens.put("access_token", accessToken);
        mapTokens.put("refresh_token", refreshToken);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), mapTokens); // On met nos tokens dans une map, que l'on retournera en responseBody si l'authent s'est bien passée.
    }
}
