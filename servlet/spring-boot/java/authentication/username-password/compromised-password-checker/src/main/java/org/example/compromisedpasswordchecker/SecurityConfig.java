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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceMethodArgumentResolver;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new ChangePasswordAdviceMethodArgumentResolver());
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.passwordManagement(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	InMemoryUserDetailsManager users() {
		UserDetails compromised = User.withDefaultPasswordEncoder()
			.username("compromised")
			.password("password")
			.roles("USER")
			.build();
		return new InMemoryUserDetailsManager(compromised);
	}

	@Bean
	ChangePasswordAdvisor changePasswordAdvisor() {
		ChangeCompromisedPasswordAdvisor compromised = new ChangeCompromisedPasswordAdvisor();
		compromised.setAction(ChangePasswordAdvice.Action.MUST_CHANGE);
		return compromised;
	}
}
