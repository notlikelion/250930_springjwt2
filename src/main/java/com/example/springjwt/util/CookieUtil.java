package com.example.springjwt.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

// JWT를 저장해주는 공간 -> 읽어들여오거나 삭제하는 작업.
public class CookieUtil {
    // 쿠키를 추가
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        // name -> accessToken, value -> jwt토큰값, maxAge -> jwt토큰의 유효기간
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/"); // 이 경로에 있는 모든 페이지에서 이 쿠키를 쓸 수 있게
        cookie.setMaxAge(maxAge);
        cookie.setHttpOnly(true); // javascript 접근 금지 -> 유저와 서버만 볼 수 있게
        response.addCookie(cookie); // 응답에 추가
    }

    // 쿠키를 가져오기
    public static Optional<String> getCookie(HttpServletRequest request, String name) {
        // 요청객체 -> 리스트 -> 순서대로 순회해가지고 내가 찾으려는 key(name)의 쿠키가 있는지, 있으면 Return. 없으면 empty. Optional.
        // 없는 조건? : 유저가 직접 지웠거나, 만료시간이 지나서 x. 우리가 지웠거나...
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie.getValue());
                    // accessToken -> value.
                }
            }
        }
        return Optional.empty();
    }

    // 쿠키를 삭제 -> 로그아웃. 쿠키의 특정한 이름에 값 자체도 ""로 덮어씌우고, 유효기간도 0.
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0); // 만료
                    response.addCookie(cookie);
                }
            }
        }
    }
}
