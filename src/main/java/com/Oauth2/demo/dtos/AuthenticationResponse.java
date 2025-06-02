package com.Oauth2.demo.dtos;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthenticationResponse {

    private String jwt;

    private Long userId;
}
