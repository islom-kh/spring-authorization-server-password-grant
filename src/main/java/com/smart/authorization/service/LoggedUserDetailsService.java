package com.smart.authorization.service;

import com.smart.authorization.domain.User;
import com.smart.authorization.dto.LoggedUser;
import com.smart.authorization.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Author: rustam.akhmedov@gmail.com
 * Date: 3/1/18
 * Time: 12:12
 */

@Service
@RequiredArgsConstructor
public class LoggedUserDetailsService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found with email=" + username));
        LoggedUser principal = new LoggedUser(user);
        return principal;
    }
}
