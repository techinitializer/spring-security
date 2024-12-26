package com.techinitializer.spring_security.config;

import com.techinitializer.spring_security.filter.CustomUsernamePasswordAuthenticationFilter;
import com.techinitializer.spring_security.service.UsernamePasswordAuthenticationProvider;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter) throws Exception {
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        http
                .headers((headers) -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable())) // just for h2-console
                .securityContext(context -> context.requireExplicitSave(false))
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/test/secured").hasRole("ADMIN")
                        .requestMatchers("/test/secured").authenticated()
                        .requestMatchers("/api/auth/**", "/h2-console/**", "/test/unsecured").permitAll()
                )
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/api/auth/**", "/h2-console/**"))
                .addFilterAt(customUsernamePasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout((logout) -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessHandler(((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.getWriter().write("Logout Successful !!");
                        }))
                );

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new UsernamePasswordAuthenticationProvider();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomUsernamePasswordAuthenticationFilter customUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new CustomUsernamePasswordAuthenticationFilter(authenticationManager);
    }
}
