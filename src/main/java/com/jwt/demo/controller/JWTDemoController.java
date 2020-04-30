package com.jwt.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.demo.model.AuthenticationRequest;
import com.jwt.demo.model.AuthenticationResponse;
import com.jwt.demo.model.MyUserDetailsService;
import com.jwt.demo.util.JwtUtil;

@RestController
public class JWTDemoController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService userDetailsService;

	@Autowired
	private JwtUtil util;

	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {

		// Authenticate Credentials
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthenticationResponse(""));
		}

		UserDetails user = userDetailsService.loadUserByUsername(request.getUserName());

		String jwt = util.generateToken(user);

		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

	@GetMapping("/hello")
	public String greet() {
		return "<h3>Hello, world!!!</h3>";
	}
}
