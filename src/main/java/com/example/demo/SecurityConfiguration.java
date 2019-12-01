package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

                .authorizeRequests()
                .antMatchers("/")
                .access("hasAnyAuthority(('USER'),'ADMIN','TEACH')")
                .antMatchers("/teacher")
                .access("hasAnyAuthority('TEACH','ADMIN')")
                .antMatchers("/course")
                .access("hasAnyAuthority('TEACH','ADMIN','USER')")
                .antMatchers("/student")
                .access("hasAuthority('USER')")
                .anyRequest().authenticated()
                .and().formLogin().loginPage("/login").permitAll();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.inMemoryAuthentication()
                .withUser("dave").password(passwordEncoder().encode("todiworld")).authorities("ADMIN")
    .and().withUser("alton").password(passwordEncoder().encode("todiworld1")).authorities("TEACH")
    .and().withUser("bri").password(passwordEncoder().encode("todiworld2")).authorities("USER");
    }
}

