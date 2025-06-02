package com.Oauth2.demo.services;

import com.Oauth2.demo.dtos.SignupRequest;
import com.Oauth2.demo.dtos.UserDto;
import com.Oauth2.demo.entities.User;
import com.Oauth2.demo.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImplementation implements AuthService {

    private final UserRepository userRepository;


    public AuthServiceImplementation(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    private final UserDto createdUserDto = new UserDto();

    @Override
    @Transactional
    public UserDto createUser(SignupRequest signupRequest) {
        if (userRepository.findByEmail(signupRequest.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists baby!");
        }

        if (userRepository.findByUsername(signupRequest.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists Baby!");
        }
        User user = new User();
        user.setEmail(signupRequest.getEmail());
        user.setUsername(signupRequest.getUsername());
        user.setName(signupRequest.getName());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        User createdUser = userRepository.save(user);
        createdUserDto.setId(createdUser.getId());
        createdUserDto.setEmail(createdUser.getEmail());
        createdUserDto.setUsername(createdUser.getUsername());
        createdUserDto.setName(createdUser.getName());
        createdUserDto.setPassword(createdUser.getPassword());
        return createdUserDto;
    }

}
