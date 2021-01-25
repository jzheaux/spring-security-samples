/*
 * Copyright 2020 the original author or authors.
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

package example.web;

import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsSignerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A controller for the token resource.
 *
 * @author Josh Cummings
 */
@RestController
public class TokenController {

	@Autowired
	JwsSignerFactory signerFactory;

	@PostMapping("/token")
	public String token(Authentication authentication) {
		String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
		return this.signerFactory.signer().issuer("self").claim("scope", scope).sign().getTokenValue();
	}

	@PostMapping("/token/{for}")
	public String tokenFor(@PathVariable("for") String user,
			@RequestParam(name = "scope", required = false) String scope) {
		Jwt.JwsSpec<?> spec = this.signerFactory.signer().issuer("self")
				// here, I override the subject that the application is defaulting to the
				// currently logged-in user
				.subject(user);
		if (StringUtils.hasText(scope)) {
			spec.claim("scope", scope);
		}
		return spec.sign().getTokenValue();
	}

}
