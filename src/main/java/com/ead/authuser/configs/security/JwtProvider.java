package com.ead.authuser.configs.security;

import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.stream.Collectors;

@Log4j2
@Component
public class JwtProvider {

    @Value("${ead.auth.jwtSecret}")
    private String jwtSecret;

    @Value("${ead.auth.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String generateJwt(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        Date now = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.MILLISECOND, Integer.valueOf(jwtExpirationMs));

        final String roles = userDetails.getAuthorities().stream()
                .map(role -> role.getAuthority())
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject((userDetails.getUserId().toString()))
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(calendar.getTime())
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getSubjectJwt(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwt(String authToken) {

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
