package com.Oauth2.demo.services;

import com.Oauth2.demo.dtos.SignupRequest;
import com.Oauth2.demo.dtos.UserDto;

public interface AuthService {

    UserDto createUser(SignupRequest signupRequest);
}
