package io.getarrays.securecapita.configuration;

import io.getarrays.securecapita.handler.CustomAccessDeniedHandler;
import io.getarrays.securecapita.handler.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;






//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
//@RequiredArgsConstructor
//public class SecurityConfig {
//    private final BCryptPasswordEncoder encoder;
//    private final CustomAccessDeniedHandler customAccessDeniedHandler;
//    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
//    private final UserDetailsService userDetailsService;
//
//    private static final String[] PUBLIC_URLS = { "/user/login/**", "/user/verify/code/**", "/user/login" };
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable().cors().disable();
//        http.sessionManagement().sessionCreationPolicy(STATELESS);
//        http.authorizeHttpRequests().requestMatchers(PUBLIC_URLS).permitAll();
//        http.authorizeHttpRequests().requestMatchers(DELETE, "/user/delete/**").hasAnyAuthority("DELETE:USER");
//        http.authorizeHttpRequests().requestMatchers(DELETE, "/customer/delete/**").hasAnyAuthority("DELETE:CUSTOMER");
//        http.exceptionHandling().accessDeniedHandler(customAccessDeniedHandler).authenticationEntryPoint(customAuthenticationEntryPoint);
//        http.authorizeHttpRequests().anyRequest().authenticated();
//        return http.build();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager() {
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(userDetailsService);
//        authProvider.setPasswordEncoder(encoder);
//        return new ProviderManager(authProvider);
//    }
//
//    /* Documentations
//    https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/UsernamePasswordAuthenticationFilter.html
//
//    https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/AuthenticationManager.html
//
//    https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/AuthenticationProvider.html
//
//    https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/dao/DaoAuthenticationProvider.html
//
//    https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/dao/AbstractUserDetailsAuthenticationProvider.html
//    */
//}
//



@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final BCryptPasswordEncoder encoder;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final UserDetailsService userDetailsService;

    private static final String[] PUBLIC_URLS = {"/user/verify/password/**",
            "/user/login/**", "/user/verify/code/**", "/user/register/**", "/user/resetpassword/**", "/user/verify/account/**",
            "/user/refresh/token/**", "/user/image/**", "/user/new/password/**"};

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable().cors();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeHttpRequests().requestMatchers(PUBLIC_URLS).permitAll();
        // http.authorizeHttpRequests().requestMatchers(OPTIONS).permitAll(); // Not needed
        http.authorizeHttpRequests().requestMatchers(DELETE, "/user/delete/**").hasAnyAuthority("DELETE:USER");
        http.authorizeHttpRequests().requestMatchers(DELETE, "/customer/delete/**").hasAnyAuthority("DELETE:CUSTOMER");
        http.exceptionHandling().accessDeniedHandler(customAccessDeniedHandler).authenticationEntryPoint(customAuthenticationEntryPoint);
        http.authorizeHttpRequests().anyRequest().authenticated();
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(encoder);
        return new ProviderManager(authProvider);
    }
}










