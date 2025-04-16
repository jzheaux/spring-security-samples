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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class HttpSessionPasswordAdviceRepository implements PasswordAdviceRepository {
	private static final String PASSWORD_ADVICE_ATTRIBUTE_NAME = HttpSessionPasswordAdviceRepository.class.getName() + ".PASSWORD_ADVICE";

	@Override
	public PasswordAdvisor.PasswordAdvice loadPasswordAdvice(HttpServletRequest request) {
		return (PasswordAdvisor.PasswordAdvice) request.getSession().getAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME);
	}

	@Override
	public void savePasswordAdvice(HttpServletRequest request, HttpServletResponse response, PasswordAdvisor.PasswordAdvice advice) {
		if (advice == null) {
			return;
		}
		request.getSession().setAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME, advice);
	}

	@Override
	public void removePasswordAdvice(HttpServletRequest request, HttpServletResponse response) {
		request.getSession().removeAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME);
	}
}
