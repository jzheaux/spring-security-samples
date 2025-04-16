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
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.HttpStatusAccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class PasswordResetProcessingFilter extends OncePerRequestFilter {
	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/reset-password");
	private final ChangePasswordAdvisor advisor = new ChangeCompromisedPasswordAdvisor();
	private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	private final PasswordAdviceRepository repository = new HttpSessionPasswordAdviceRepository();
	private final AuthenticationEntryPoint entryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	private final AuthorizationManager<RequestAuthorizationContext> authorizationManager =
		AuthenticatedAuthorizationManager.authenticated();
	private final AccessDeniedHandler deniedHandler = new HttpStatusAccessDeniedHandler(HttpStatus.FORBIDDEN);
	private final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private final UserDetailsPasswordService passwords;

	public PasswordResetProcessingFilter(UserDetailsPasswordService manager) {
		this.passwords = manager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		RequestMatcher.MatchResult match = this.requestMatcher.matcher(request);
		if (!match.isMatch()) {
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
			this.entryPoint.commence(request, response, new InsufficientAuthenticationException("Password reset required"));
			return;
		}
		AuthorizationResult authorization = this.authorizationManager.authorize(() -> authentication,
			new RequestAuthorizationContext(request, match.getVariables()));
		if (authorization == null) {
			this.deniedHandler.handle(request, response, new AuthorizationDeniedException("denied"));
			return;
		}
		if (!authorization.isGranted()) {
			this.deniedHandler.handle(request, response, new AuthorizationDeniedException("access denied", authorization));
			return;
		}
		UserDetails user = (UserDetails) authentication.getPrincipal();
		ChangePasswordAdvice advice = this.advisor.advise(new ChangePasswordAdvisor.ChangeUpdatedPasswordAdviceRequest(user, password));
		if (advice == ChangePasswordAdvice.KEEP) {
			this.passwords.updatePassword(user, this.encoder.encode(password));
			this.repository.removePasswordAdvice(request, response);
		} else {
			this.repository.savePasswordAdvice(request, response, advice);
		}
		this.successHandler.onAuthenticationSuccess(request, response, authentication);
	}


}
