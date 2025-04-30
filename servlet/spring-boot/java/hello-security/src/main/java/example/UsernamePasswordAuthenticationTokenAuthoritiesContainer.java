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

import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class UsernamePasswordAuthenticationTokenAuthoritiesContainer extends UsernamePasswordAuthenticationToken
	implements AuthoritiesContainer {

	public UsernamePasswordAuthenticationTokenAuthoritiesContainer(Object principal, Object credentials) {
		super(principal, credentials);
	}

	public UsernamePasswordAuthenticationTokenAuthoritiesContainer(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}

	@Override
	public Authentication authorities(Consumer<Collection<GrantedAuthority>> authoritiesConsumer) {
		Collection<GrantedAuthority> authorities = new ArrayList<>(getAuthorities());
		authoritiesConsumer.accept(authorities);
		return new UsernamePasswordAuthenticationTokenAuthoritiesContainer(getPrincipal(), getCredentials(), authorities);
	}
}
