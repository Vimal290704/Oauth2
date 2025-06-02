package com.Oauth2.demo.dtos;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthenticationRequest {

    private String email;

    private String password;
}
