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

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	WebMvcConfigurer argumentResolvers(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		return new WebMvcConfigurer() {
			@Override
			public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
				ChangePasswordAdviceMethodArgumentResolver resolver = new ChangePasswordAdviceMethodArgumentResolver();
				resolver.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
				resolvers.add(resolver);
			}
		};
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.with(new PasswordManagementConfigurer<>(context), Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	InMemoryUserDetailsManager users() {
		String tooLongPassword = "{bcrypt}$2a$10$ZI9RHDidWWbUJ38noohrsOUEDod2v15BEa.3gpQQ5kUoDWKr3yOD6";
		String adminPassword = "{bcrypt}$2a$10$O7yxTCDZXQ0H6G2dLZpMS.a0e4Lfv1t4/JhHjrsL5BAk4.ZkT.fyG";

		UserDetails compromised = User.withUsername("compromised").password("{noop}password").roles("USER").build();
		UserDetails tooLong = User.withUsername("toolong").password(tooLongPassword).roles("USER").build();
		UserDetails admin = User.withUsername("admin").password(adminPassword).roles("ADMIN").build();

		return new InMemoryUserDetailsManager(compromised, tooLong, admin);
	}

	@Bean
	ChangePasswordAdviceRepository changePasswordAdviceRepository(ChangePasswordAdviceService passwords) {
		return new ChangePasswordAdviceServiceRepository(passwords);
	}

	@Bean
	ChangePasswordAdviceService changePasswordService() {
		return new InMemoryChangePasswordAdviceService();
	}

	@Bean
	ChangePasswordAdvisor changePasswordAdvisor(UserDetailsService users, ChangePasswordAdviceService passwords) {
		return new DelegatingChangePasswordAdvisor(List.of(
			new ChangeCompromisedPasswordAdvisor(),
			new ChangeRepeatedPasswordAdvisor(users),
			new ChangeLengthPasswordAdvisor(8, 72),
			new ChangePasswordServiceAdvisor(passwords)));
	}

}
