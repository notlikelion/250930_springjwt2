package com.example.springjwt.filter;

import com.example.springjwt.util.CookieUtil;
import com.example.springjwt.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    // 모든 요청에 대해 한 번만(씩) 실행되는 필터 로직 -> 너 JWT 토큰 있니?
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request -> header -> cookie -> accessToken
        Optional<String> accessToken = CookieUtil.getCookie(request, "accessToken");
        // request -> accessToken 쿠키를 받아오겠다
        if (accessToken.isPresent() && jwtUtil.validateToken(accessToken.get())) {
            // 토큰에서 사용자 이름을 추출
            String username = jwtUtil.getUsernameFromToken(accessToken.get());

            UsernamePasswordAuthenticationToken authentication
                    = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority(("ROLE_USER")))
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }
}
