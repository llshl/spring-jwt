package com.example.jwtsecurity.service;

import com.example.jwtsecurity.dto.TokenResponse;
import com.example.jwtsecurity.dto.UserRequest;
import com.example.jwtsecurity.entity.Auth;
import com.example.jwtsecurity.entity.User;
import com.example.jwtsecurity.jwt.JwtTokenProvider;
import com.example.jwtsecurity.repository.AuthRepository;
import com.example.jwtsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public TokenResponse register(UserRequest userRequest){
        User user = User.builder()
                .userId(userRequest.getUserId())
                .userPw(passwordEncoder.encode(userRequest.getUserPw()))
                .build();
        userRepository.save(user);

        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());
        Auth auth = Auth.builder()
                .user(user)
                .refreshToken(refreshToken)
                .build();
        authRepository.save(auth);
        return TokenResponse.builder()
                .ACCESS_TOKEN(accessToken)
                .REFRESH_TOKEN(refreshToken)
                .build();
    }

    @Transactional
    public TokenResponse doLogin(UserRequest userRequest) throws Exception {
        User user = userRepository.findByUserId(userRequest.getUserId())
                        .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 회원입니다."));
        Auth auth = authRepository.findByUserId(user.getId())
                        .orElseThrow(() -> new IllegalArgumentException("Token 이 존재하지 않습니다."));
        if (!passwordEncoder.matches(userRequest.getUserPw(), user.getUserPw())) {
            throw new Exception("비밀번호가 일치하지 않습니다.");
        }

        String accessToken = "";
        String refreshToken = auth.getRefreshToken();

        //refresh 토큰은 유효 할 경우
        if (jwtTokenProvider.isValidRefreshToken(refreshToken)) {
            accessToken = jwtTokenProvider.createAccessToken(user.getUserId()); //Access Token 새로 만들어서 줌
            return TokenResponse.builder()
                    .ACCESS_TOKEN(accessToken)
                    .REFRESH_TOKEN(refreshToken)
                    .build();
        } else {
            //둘 다 새로 발급
            accessToken = jwtTokenProvider.createAccessToken(user.getUserId());
            refreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());
            auth.refreshUpdate(refreshToken);
        }

        return TokenResponse.builder()
                .ACCESS_TOKEN(accessToken)
                .REFRESH_TOKEN(refreshToken)
                .build();
    }

    public Optional<User> findByUserId(String userID){
        return userRepository.findByUserId(userID);
    }
}
