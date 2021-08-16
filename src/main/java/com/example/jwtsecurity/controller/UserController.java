package com.example.jwtsecurity.controller;


import com.example.jwtsecurity.dto.TokenResponse;
import com.example.jwtsecurity.dto.UserRequest;
import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.jwt.JwtTokenProvider;
import com.example.jwtsecurity.repository.UserRepository;
import com.example.jwtsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final UserService userService;

    // 회원가입
    @PostMapping("/join")
    public ResponseEntity join(@RequestBody UserRequest userRequest) {
        if(userService.findByUserId(userRequest.getUserId()).isPresent())
            return ResponseEntity.badRequest().build();
        else
            return ResponseEntity.ok(userService.register(userRequest));
    }

    // 로그인
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody UserRequest userRequest) throws Exception {
        return ResponseEntity
                .ok()
                .body(userService.doLogin(userRequest));
    }

    @PostMapping("/user/test")
    public Map userResponseTest() {
        Map<String, String> result = new HashMap<>();
        result.put("result","user ok");
        return result;
    }

//    @PostMapping("/admin/test")
//    public Map adminResponseTest() {
//        Map<String, String> result = new HashMap<>();
//        result.put("result","admin ok");
//        return result;
//    }
}
