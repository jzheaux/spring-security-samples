/*
 * Copyright 2025 the original author or authors.
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

package org.example.compromisedpasswordchecker;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class PasswordResetProcessingFilter extends OncePerRequestFilter {
	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/reset-password");
	private final PasswordResetAdvisor advisor = new SimplePasswordResetChecker();
	private final PasswordResetHandler handler = new SimplePasswordResetHandler();
	private final UserDetailsManager manager;

	public PasswordResetProcessingFilter(UserDetailsManager manager) {
		this.manager = manager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		String password = request.getParameter("password");
		if (password == null) {
			chain.doFilter(request, response);
			return;
		}
		String oldPassword = request.getParameter("old_password");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new InsufficientAuthenticationException("authentication required");
		}
		PasswordResetAdvisor.PasswordAdvice advice = this.advisor.check(authentication, password);
		if (advice == PasswordResetAdvisor.PasswordAdvice.KEEP) {
			this.manager.changePassword(oldPassword, password);
		}
		this.handler.handle(request, response, chain, advice);
	}
}
