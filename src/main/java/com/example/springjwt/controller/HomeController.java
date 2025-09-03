package com.example.springjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, Authentication authentication) {
        // login한 username을 가져오려고...
        // String username = SecurityContextHolder.getContext().getAuthentication().getName();
        String username = authentication.getName();
        model.addAttribute("username", username);
        return "home";
    }
}
