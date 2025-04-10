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

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

public class SimplePasswordResetHandler implements PasswordResetHandler {
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private final PasswordResetAdviceRepository advice = new HttpSessionPasswordResetAdviceRepository();

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, FilterChain chain, PasswordResetAdvisor.PasswordAdvice advice)
		throws IOException, ServletException {
		if (advice == null) {
			chain.doFilter(request, response);
			return;
		}
		if (advice == PasswordResetAdvisor.PasswordAdvice.KEEP) {
			this.advice.removePasswordResetAdvice(request, response);
			chain.doFilter(request, response);
			return;
		}
		if (advice == PasswordResetAdvisor.PasswordAdvice.RESET) {
			this.advice.savePasswordResetAdvice(request, response, advice);
			chain.doFilter(request, response);
			return;
		}
		if (advice == PasswordResetAdvisor.PasswordAdvice.REQUIRE_RESET) {
			this.advice.savePasswordResetAdvice(request, response, advice);
			this.redirectStrategy.sendRedirect(request, response, "/reset-password");
		}
	}
}
