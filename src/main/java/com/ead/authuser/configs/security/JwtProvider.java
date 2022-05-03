package com.ead.authuser.configs.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

@Log4j2
@Component
public class JwtProvider {

    @Value("${ead.auth.jwtSecret}")
    private String jwtSecret;

    @Value("${ead.auth.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String generateJwt(Authentication authentication) {
        UserDetails userDetails = (UserDetailsImpl) authentication.getPrincipal();

        Date now = new Date();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.MILLISECOND, Integer.valueOf(jwtExpirationMs));

        return Jwts.builder()
                .setSubject((userDetails.getUsername()))
                .setIssuedAt(now)
                .setExpiration(calendar.getTime())
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
}
