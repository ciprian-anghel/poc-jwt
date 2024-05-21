package com.mizu.pocjwt.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

	private final JwtAuthenticationFilter jwtAuthFilter;
	private final UserDetailsService userDetailsService;
	
	private static final String[] WHITE_LIST_URL = {
			"/api/v1/auth/**"
	};
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
//			.cors(cors -> cors.configurationSource(new CustomCorsConfig())) //NOT NEEDED FOR THIS POC BUT ADDED FOR REFERENCE
			.authorizeHttpRequests(req -> req
					.requestMatchers(WHITE_LIST_URL).permitAll()
					.anyRequest().authenticated())
			.sessionManagement(customizer -> customizer.sessionCreationPolicy(
					SessionCreationPolicy.STATELESS))
			.authenticationProvider(authenticationProvider())
			.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
	
	@SuppressWarnings("unused")
	private class CustomCorsConfig implements CorsConfigurationSource {
    	@Override
		public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
			CorsConfiguration config = new CorsConfiguration();
			config.setAllowCredentials(true);
			config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
			config.setAllowedHeaders(Arrays.asList(
					HttpHeaders.AUTHORIZATION,
					HttpHeaders.CONTENT_TYPE,
					HttpHeaders.ACCEPT
			));
			config.setAllowedMethods(Arrays.asList(
					HttpMethod.GET.name(),
					HttpMethod.POST.name(),
					HttpMethod.PUT.name(),
					HttpMethod.DELETE.name()
			));
			config.setMaxAge(3600L);
			
	        return config;
		}
    }
	
}