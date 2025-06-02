package com.Oauth2.demo.dtos;

import lombok.Data;

@Data
public class UserDto {

    private Long id;

    private String username;

    private String email;

    private String name;

    private String password;
}
