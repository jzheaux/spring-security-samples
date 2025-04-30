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

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

public class AuthorizationRequestUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	AuthorizationRequestRepository authorizationRequests = new HttpSessionAuthorizationRequestRepository();

	public AuthorizationRequestUsernamePasswordAuthenticationFilter(UserDetailsService users) {
		super(new DaoAuthenticationProvider(users) {
			@Override
			protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
				Authentication result = super.createSuccessAuthentication(principal, authentication, user);
				return new UsernamePasswordAuthenticationTokenAuthoritiesContainer(result.getPrincipal(), result.getCredentials(), result.getAuthorities());
			}
		}::authenticate);
		setSecurityContextRepository(new HttpSessionSecurityContextRepository());
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		Authentication authentication = super.attemptAuthentication(request, response);
		if (!(authentication instanceof AuthoritiesContainer container)) {
			return authentication;
		}
		AuthorizationRequest authorizationRequest = this.authorizationRequests.removeAuthorizationRequest(request);
		if (authorizationRequest == null) {
			return authentication;
		}
		Collection<GrantedAuthority> granted = authorizationRequest.getAuthorities()
			.stream().map((a) -> new RevocableGrantedAuthority(a.getAuthority(), Instant.now().plusMillis(60000L)))
			.collect(Collectors.toList());
		return container.authorities((authorities) -> authorities.addAll(granted));
	}
}
