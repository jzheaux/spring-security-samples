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

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class PasswordCheckingUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final PasswordResetAdvisor checker = new SimplePasswordResetChecker();
	private final PasswordResetHandler handler = new SimplePasswordResetHandler();

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		String password = obtainPassword(request);
		PasswordResetAdvisor.PasswordAdvice advice = this.checker.check(authResult, password);
		this.handler.handle(request, response, (req, res) -> {}, advice);
		super.successfulAuthentication(request, response, chain, authResult);
	}

}
