package com.mizu.pocjwt.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mizu.pocjwt.dto.AuthenticationRequest;
import com.mizu.pocjwt.dto.AuthenticationResponse;
import com.mizu.pocjwt.dto.RegisterRequest;
import com.mizu.pocjwt.services.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	
	private final AuthenticationService authenticationService;

	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
		return ResponseEntity.ok(authenticationService.register(request));
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
		return ResponseEntity.ok(authenticationService.authenticate(request));
	}
	
}
