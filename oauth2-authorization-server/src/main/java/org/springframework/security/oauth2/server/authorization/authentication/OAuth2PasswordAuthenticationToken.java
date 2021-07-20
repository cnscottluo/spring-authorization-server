package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;

/**
 * <p>
 *
 * </p>
 *
 * @author scottluo
 * @since 2021/7/21
 */
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String username;
	private final String password;
	private final Collection<GrantedAuthority> authorities;


	public OAuth2PasswordAuthenticationToken(String username, String password,Collection<GrantedAuthority> authorities, Authentication clientPrincipal, Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
		Assert.hasText(username, "username cannot be empty");
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}
}
