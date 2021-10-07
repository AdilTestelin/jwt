package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response); // Si le path est le login, on ne fait rien concernant les requêtes.
        } else {
            // Sinon, on rentre dans le filtre.
            String authorizationHeader = request.getHeader(AUTHORIZATION); // On recupère notre header, qui contient notre Token.
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    String token = authorizationHeader.substring("Bearer ".length()); // On recupère notre JWT.
                    Algorithm algo = Algorithm.HMAC256("secret".getBytes()); // On réinstancie l'algo qui permettra cette fois de le décoder.
                    JWTVerifier verifier = JWT.require(algo).build();
                    DecodedJWT decodedJWT = verifier.verify(token); // On décode notre JWT.
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class); // On récupère le username, ainsi que les roles.
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    }); // On recréé notre liste de droits.
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken); // On recréé un authenticationToken, que l'on mettra dans notre contexte SpringSecurity : notre app sait désormais que nous sommes authentifiés.
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    log.error("Error logging in {}", e.getMessage());
                    response.setHeader("error", e.getMessage());
                    // response.setStatus(FORBIDDEN.value());
                    Map<String, String> errors = new HashMap<>();
                    errors.put("error_message", e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), errors);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
