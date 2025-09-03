package com.example.springjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component // Scan -> 등록
public class JwtUtil {
    // https://jwtsecrets.com/ -> application -> 저장 불러쓰기
    // 1. 파일 자체에 넣어쓰고 대신 git에 안올리기
    // 2. 환경변수로 불러오도록 하고 이러면 git에 올려도 된다
    private final SecretKey secretKey; // 비밀키 -> JWT 토큰을 만들 때/ 해석할 때 쓰일 암호화 키
    private final Long accessTokenExpiration; // 만료시간
    // [생성자 주입], 필드 주입, 세터 주입 ???
    // (순환 참조 문제...)

    // application.properties 또는 yml에 있는 값을 불러오는 것.
    public JwtUtil(@Value("${jwt.secret}") String secret, @Value("${jwt.access-token-expiration}") Long accessTokenExpiration) {
        System.out.println("secret: " + secret);
        System.out.println("accessTokenExpiration: " + accessTokenExpiration);
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public String createAccessToken(String username) {
        return createToken(username, accessTokenExpiration);
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public String createToken(String username, Long expiration) {
        // 토큰을 만들 때는 만료일, 변환 로직
        Date now = new Date(); // 어차피 이걸 long -> 어떤 시간대에 있든 실질적으로는 UTC.
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(username) // 주요내용(유저이름)
                .issuedAt(now) // 발급일시
                .expiration(expiryDate) // 만료일시
                .signWith(secretKey) // 서명시 사용할 비밀키
                .compact(); // JWT 문자열 생성
    }

    public boolean validateToken(String token) {
        try {
            // 형식이 안맞으면 에러가 난다 -> xxxxxxx:yyyyyy:zzzzz? 혹은 secret key로 뭔가 해석이 안된다
            getClaims(token);
            return true;
        } catch (Exception e) {
            // 만료, 형식 오류...
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject(); // subject -> username
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token) // token -> secretKey sign claim
                .getPayload(); // payload -> data
        // subject -> username
        // 발행일시, 만료일시...
    }
}