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

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class RevocableAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
	private final Collection<GrantedAuthority> authorities;

	RevocableAuthorizationManager(Collection<GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		Collection<String> granted = authentication.get().getAuthorities().stream()
			.filter((a) -> !(a instanceof RevocableGrantedAuthority recoverable) || !recoverable.isRevoked())
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.toSet());
		Collection<GrantedAuthority> required = this.authorities.stream()
			.filter((a) -> !granted.contains(a.getAuthority())).collect(Collectors.toSet());
		return (required.isEmpty()) ? new AuthorizationDecision(true) : new AuthorityAuthorizationDecision(false, required);
	}

	public static RevocableAuthorizationManager hasAuthority(String authority) {
		return new RevocableAuthorizationManager(List.of(new SimpleGrantedAuthority(authority)));
	}
}
