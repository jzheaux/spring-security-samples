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

package example;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public final class HttpSessionAuthorizationRequestRepository implements AuthorizationRequestRepository {

	private static final String AUTHORIZATION_REQUEST_ATTR = HttpSessionAuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST";

	@Override
	public AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		String id = request.getParameter("authorization_request_id");
		AuthorizationRequest authorizationRequest = (AuthorizationRequest) request.getSession().getAttribute(AUTHORIZATION_REQUEST_ATTR);
		if (id == null) {
			return authorizationRequest;
		}
		if (authorizationRequest.getId().equals(id)) {
			return authorizationRequest;
		}
		return null;
	}

	@Override
	public void saveAuthorizationRequest(HttpServletRequest request, HttpServletResponse response, AuthorizationRequest authorizationRequest) {
		request.getSession().setAttribute(AUTHORIZATION_REQUEST_ATTR, authorizationRequest);
	}

	@Override
	public AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
		if (authorizationRequest == null) {
			return null;
		}
		request.getSession().removeAttribute(AUTHORIZATION_REQUEST_ATTR);
		return authorizationRequest;
	}
}
