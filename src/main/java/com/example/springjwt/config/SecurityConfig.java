package com.example.springjwt.config;

import com.example.springjwt.filter.JwtAuthenticationFilter;
import com.example.springjwt.filter.JwtAuthorizationFilter;
import com.example.springjwt.util.CookieUtil;
import com.example.springjwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtUtil jwtUtil;
    private final AuthenticationConfiguration authenticationConfiguration;
    // 의존성 주입 -> 생성자 주입 -> @RequiredArgsConstructor

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF : Cross-Site-Request-Forgery -> 다른 페이지에서 폼 등의 방식으로 post 등의 주요 요청을 보내는 공격. (사칭)
        // CORS는 출처(origin) / 실제 유저 -> 다른 사이트인 척을 하는 사이트 -> 실제 사이트
        // https://developer.mozilla.org/ko/docs/Glossary/CSRF
        // Spring Security는 Thymeleaf 등과 사용을 하면 CSRF 토큰이라는 걸 기본적인 걸로 채택
        // -> token할 때는 굳이 csrf가 필요가 없음.
//        http.csrf(csrf -> csrf.disable());
        // CSRF 비활성화
        http.csrf(AbstractHttpConfigurer::disable);
        // 세션 비활성화
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // 폼 로그인 비활성화
//        http.formLogin(form -> form.disable());
        http.formLogin(AbstractHttpConfigurer::disable);
        // HTTP Basic 인증 방식 비활성화
//        http.httpBasic(basic -> basic.disable());
        http.httpBasic(AbstractHttpConfigurer::disable);

        // URL별 접근 권한 설정
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/api/login").permitAll()
                .anyRequest().authenticated()
        ); // 로그인만 모두가 들어가고 나머지는 로그인해야...

        // 로그아웃
        // 세션 -> 세션만료
        // 쿠키 -> 쿠키에 토큰에 담았음 -> 쿠키 삭제.
        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(((request, response, authentication) -> {
                    CookieUtil.deleteCookie(request, response, "accessToken");
                    response.sendRedirect("/login");
                }))
        );

        // JWT 필터
        // JwtAuthentication Filter - 토큰에 들어가 있는 내용을 검증하는 역할
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtUtil, authenticationManager(authenticationConfiguration));
        jwtAuthenticationFilter.setFilterProcessesUrl("/api/login"); // 로그인처리 URL -> 필터
        http.addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // JwtAuthorization Filter - 토큰을 발급, 서식 검증하는 역할
        http.addFilterBefore(new JwtAuthorizationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
