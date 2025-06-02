package com.Oauth2.demo.dtos;


import lombok.Data;

@Data
public class SignupRequest {

    private String username;

    private String email;

    private String name;

    private String password;

}
