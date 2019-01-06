package com.mightyjava.service.impl;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.mightyjava.model.User;
import com.mightyjava.repository.UserRepository;

@Service
public class CustomAuthenticationProviderService implements AuthenticationProvider {
	
	@Autowired
	private UserRepository userRepository;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken authenticationToken = null;
		
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();
		
		User user = userRepository.findByUsername(username);
		if(user != null) {
			if(username.equals(user.getUserName()) && BCrypt.checkpw(password, user.getPassword())) {
				Collection<GrantedAuthority> grantedAuthorities = getGrantedAuthorities(user);
				authenticationToken = new UsernamePasswordAuthenticationToken(
						new org.springframework.security.core.userdetails.User(username, password, grantedAuthorities), password, grantedAuthorities);
			}
		} else {
			throw new UsernameNotFoundException("User name "+username+" not found");
		}
		return authenticationToken;
	}

	private Collection<GrantedAuthority> getGrantedAuthorities(User user) {
		Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		if(user.getRole().getName().equals("admin")) {
			grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}
		grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		return grantedAuthorities;
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
