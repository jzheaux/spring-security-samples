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
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class PasswordResetProcessingFilter extends OncePerRequestFilter {
	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/reset-password");
	private final PasswordAdvisor advisor = new SimplePasswordResetAdvisor();
	private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	private final PasswordAdviceRepository repository = new HttpSessionPasswordAdviceRepository();
	private final UserDetailsPasswordService users;

	public PasswordResetProcessingFilter(UserDetailsPasswordService manager) {
		this.users = manager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		String password = request.getParameter("newPassword");
		if (password == null) {
			chain.doFilter(request, response);
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new InsufficientAuthenticationException("authentication required");
		}
		String oldPassword = request.getParameter("currentPassword");
		UserDetails user = (UserDetails) authentication.getPrincipal();
		PasswordAdvisor.PasswordAdvice advice = this.advisor.advise(user, oldPassword, password);
		if (advice == PasswordAdvisor.PasswordAdvice.KEEP) {
			this.users.updatePassword(user, this.encoder.encode(password));
			this.repository.removePasswordAdvice(request, response);
		}
		HttpServletRequest login = new UsernamePasswordHttpServletRequest(request, user.getUsername(), password);
		request.getRequestDispatcher("/login").forward(login, response);
	}

	private static final class UsernamePasswordHttpServletRequest extends HttpServletRequestWrapper {
		private final String username;
		private final String password;

		UsernamePasswordHttpServletRequest(HttpServletRequest request, String username, String password) {
			super(request);
			this.username = username;
			this.password = password;
		}

		@Override
		public String getMethod() {
			return "POST";
		}

		@Override
		public String getParameter(String name) {
			if ("username".equals(name)) {
				return this.username;
			}
			if ("password".equals(name)) {
				return this.password;
			}
			return super.getParameter(name);
		}

	}
}
