package com.example.jwtsecurity.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TokenIndexResponse {
    private String ACCESS_TOKEN;
    private Long REFRESH_TOKEN_INDEX;
}
