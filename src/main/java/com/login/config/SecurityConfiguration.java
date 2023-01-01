package com.login.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests((authz) -> authz
//                        .requestMatchers("/index.html", "/", "**/home", "**/login")
//                        .permitAll()
//                        .anyRequest().authenticated()
//                )
//                .httpBasic(withDefaults());
//
//        return http.build();

    /*
     https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
     https://docs.spring.io/spring-security/reference/servlet/architecture.html
    */

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(auth -> auth
//                        .anyRequest()
//                        .authenticated())
//                .authorizeHttpRequests()
//                .and()
//                .httpBasic(withDefaults());
        http
                .authorizeRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(withDefaults())
                .httpBasic(withDefaults());
        return http.build();
    }

//    }
}