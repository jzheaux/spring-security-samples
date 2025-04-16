/*
 * Copyright 2024 the original author or authors.
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

import java.util.List;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

	Log logger = LogFactory.getLog(SecurityConfig.class);

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new PasswordAdviceMethodArgumentResolver());
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ExpirationUpdatingUserDetailsManager users, AuthenticationManager authenticationManager) throws Exception {
		PasswordCheckingUsernamePasswordAuthenticationFilter filter = new PasswordCheckingUsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(authenticationManager);
		filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.addFilterBefore(new DefaultPasswordResetPageGeneratingFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new PasswordResetProcessingFilter(users), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new PasswordAdvisingFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterAt(filter, UsernamePasswordAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}


	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	DaoAuthenticationProvider authenticationProvider(UserDetailsService users) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(users);
		provider.setPostAuthenticationChecks((user) -> {});
		return provider;
	}

	@Bean
	ExpirationUpdatingUserDetailsManager users() {
		UserDetails compromised = User.withDefaultPasswordEncoder()
			.username("compromised")
			.password("password")
			.roles("USER")
			.build();
		String random = UUID.randomUUID().toString();
		UserDetails expired = User.withDefaultPasswordEncoder()
			.username("user")
			.password(random)
			.roles("USER")
			.credentialsExpired(true)
			.build();
		this.logger.info("expired password: " + random);
		InMemoryUserDetailsManager delegate = new InMemoryUserDetailsManager(compromised, expired);
		return new ExpirationUpdatingUserDetailsManager(delegate);
	}

}
