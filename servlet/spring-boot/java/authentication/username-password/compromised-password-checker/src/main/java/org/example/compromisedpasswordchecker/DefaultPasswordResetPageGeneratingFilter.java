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
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class DefaultPasswordResetPageGeneratingFilter extends OncePerRequestFilter {
	private RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/reset-password");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		String page = PASSWORD_RESET_TEMPLATE;
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		if (token != null) {
			page = page
				.replace("{{parameter}}", token.getParameterName())
				.replace("{{value}}", token.getToken());
		}
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().println(page);
	}

	private static final String PASSWORD_RESET_TEMPLATE = """
		<!DOCTYPE html>
		<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="https://www.thymeleaf.org" lang="en">
		<head>
			<title>Hello Spring Security</title>
			<meta charset="utf-8" />
		</head>
		<body>
			<h3>Your password is compromised, please reset it:</h3>
			<form th:action="/reset-password" method="post">
				<label for="newPassword">New password</label>
				<input type="password" id="newPassword" name="newPassword"> <br/>
				<input type="hidden" name="{{parameter}}" value="{{value}}"/>
				<input id="submit" type="submit" value="Submit"/>
			</form>
		</body>
		</html>
		""";
}
