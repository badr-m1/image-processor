package dev.badr_m1.image_processor_api.security;

import org.springframework.stereotype.Service;

import dev.badr_m1.image_processor_api.user.Role;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {
    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @Value("${security.jwt.expiration}")
    private long jwtExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
    }

    public String generateToken(Long userId, Role role) {
        return Jwts.builder()
        .subject(userId.toString())
        .claim("role", role.name())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + jwtExpiration)
        )
        .signWith(getSigningKey())
        .compact();

    }

    public Long extractUserId(String token) {

        Claims claims = extractAllClaims(token);

        return Long.valueOf(claims.getSubject());
    }

    public Role extractRole(String token) {

        Claims claims = extractAllClaims(token);

        String role = claims.get("role", String.class);

        return Role.valueOf(role);
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}