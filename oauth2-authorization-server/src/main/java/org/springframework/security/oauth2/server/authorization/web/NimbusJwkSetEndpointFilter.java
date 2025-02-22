/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;




/**
 * A {@code Filter} that processes JWK Set requests.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see com.nimbusds.jose.jwk.source.JWKSource
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">Section 5 JWK Set Format</a>
 */
// JWT SET 端点
public class NimbusJwkSetEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for JWK Set requests.
	 */
	public static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";

	private final JWKSource<SecurityContext> jwkSource;
	private final JWKSelector jwkSelector;
	private final RequestMatcher requestMatcher;

	/**
	 * Constructs a {@code NimbusJwkSetEndpointFilter} using the provided parameters.
	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
	 */
	public NimbusJwkSetEndpointFilter(JWKSource<SecurityContext> jwkSource) {
		this(jwkSource, DEFAULT_JWK_SET_ENDPOINT_URI);
	}

	/**
	 * Constructs a {@code NimbusJwkSetEndpointFilter} using the provided parameters.
	 *
	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
	 * @param jwkSetEndpointUri the endpoint {@code URI} for JWK Set requests
	 */
	public NimbusJwkSetEndpointFilter(JWKSource<SecurityContext> jwkSource, String jwkSetEndpointUri) {
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		Assert.hasText(jwkSetEndpointUri, "jwkSetEndpointUri cannot be empty");
		this.jwkSource = jwkSource;
		this.jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
		// 匹配 /oauth2/jwks 进行拦截
		this.requestMatcher = new AntPathRequestMatcher(jwkSetEndpointUri, HttpMethod.GET.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// 如果不是访问 /oauth2/jwks 则放行
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		JWKSet jwkSet;
		try {
			// 创建 JWKSet
			jwkSet = new JWKSet(this.jwkSource.get(this.jwkSelector, null));
		}
		catch (Exception ex) {
			throw new IllegalStateException("Failed to select the JWK(s) -> " + ex.getMessage(), ex);
		}

		// 设置响应为 JSON
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		// 获取Writer
		try (Writer writer = response.getWriter()) {
			// 写出JWKSet
			writer.write(jwkSet.toString());	// toString() excludes private keys
		}
	}
}
