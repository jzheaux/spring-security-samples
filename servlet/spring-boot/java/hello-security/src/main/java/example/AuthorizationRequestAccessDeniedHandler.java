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

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.HttpStatusAccessDeniedHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

@Component
public final class AuthorizationRequestAccessDeniedHandler implements AccessDeniedHandler {

	private final RequestCache requestCache = new HttpSessionRequestCache();

	private final AccessDeniedHandler delegate = new HttpStatusAccessDeniedHandler(HttpStatus.FORBIDDEN);

	private final AuthorizationRequestHandler requestHandler = new LoginUriAuthorizationRequestHandler();

	private final AuthorizationRequestRepository authorizationRequests = new HttpSessionAuthorizationRequestRepository();

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
		throws IOException, ServletException {
		if (!(exception instanceof AuthorizationDeniedException denied)) {
			this.delegate.handle(request, response, exception);
			return;
		}
		if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision decision)) {
			this.delegate.handle(request, response, exception);
			return;
		}
		this.requestCache.saveRequest(request, response);
		AuthorizationRequest authzRequest = new AuthorizationRequest(decision.getAuthorities());
		this.authorizationRequests.saveAuthorizationRequest(request, response, authzRequest);
		this.requestHandler.handle(request, response, authzRequest);
	}

}
