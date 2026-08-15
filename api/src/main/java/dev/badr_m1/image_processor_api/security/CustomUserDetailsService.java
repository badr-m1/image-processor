package dev.badr_m1.image_processor_api.security;

import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import dev.badr_m1.image_processor_api.user.User;
import dev.badr_m1.image_processor_api.user.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found")
                );

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities("ROLE_" + user.getRole().name())
                .build();
    }
}