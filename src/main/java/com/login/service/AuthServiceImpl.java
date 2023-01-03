package com.login.service;

import com.login.controller.model.Request;
import com.login.entity.User;
import com.login.entity.UserRole;
import com.login.exception.UserException;
import com.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class AuthServiceImpl implements AuthService, UserDetailsService {

    private static final String USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE = "Username cannot be null";
    private static final String USER_MUST_BE_NOT_EMPTY_ERROR_MESSAGE = "User must be not empty";
    private static final String USER_ALREADY_EXISTS_ERROR_MESSAGE = "User already exists";
    private static final String PASSWORD_CANNOT_BE_EMPTY_ERROR_MESSAGE = "Password cannot be empty";
    private static final String REQUEST_IS_NULL_ERROR_MESSAGE = "Request is null";
    private static final String ROLES_NOT_FOUND_ERROR_MESSAGE = "Roles not found";
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    private static List<String> getRoles(Request request) {
        return Optional.ofNullable(request.getRoles())
                .orElseThrow(() -> new UserException(ROLES_NOT_FOUND_ERROR_MESSAGE));
    }

    private static String getPassword(Request request) {
        return Optional.ofNullable(request.getUserPwd())
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new UserException(PASSWORD_CANNOT_BE_EMPTY_ERROR_MESSAGE));
    }

    @Override
    public boolean isAuthenticated() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return null != authentication && !("anonymousUser").equals(authentication.getName());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null) {
            throw new UserException(USERNAME_CANNOT_BE_NULL_ERROR_MESSAGE);
        }

        final User user = userRepository.findByUserName(username).orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
        List<UserRole> userRoles = user.getUserRoles()
                .stream()
                .toList();
        final List<SimpleGrantedAuthority> grantedAuthorities = userRoles.stream()
                .map(r -> new SimpleGrantedAuthority(r.getRole())
                ).toList();

        return new org.springframework.security.core.userdetails.User(username, user.getUserPass(), grantedAuthorities);
    }

    @Override
    @Transactional
    public void saveUser(Request request) {

        if (request == null) {
            throw new UserException(REQUEST_IS_NULL_ERROR_MESSAGE);
        }

        final String userName = Optional.of(request)
                .map(Request::getUserName)
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new UserException(USER_MUST_BE_NOT_EMPTY_ERROR_MESSAGE));

        if (userRepository.findByUserName(userName).isPresent()) {
            throw new UserException(USER_ALREADY_EXISTS_ERROR_MESSAGE);
        }

        User user = new User();
        user.setUserName(userName);
        user.setUserPass(passwordEncoder.encode(getPassword(request)));

        user.setUserRoles(getRoles(request).stream().map(r -> {
            UserRole ur = new UserRole();
            ur.setRole(r);
            return ur;
        }).collect(Collectors.toSet()));

        userRepository.save(user);
    }
}
