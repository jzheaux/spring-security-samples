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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

	Log logger = LogFactory.getLog(SecurityConfig.class);

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(new ChangePasswordAdviceMethodArgumentResolver());
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectProvider<Customizer<HttpSecurity>> customizers) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults());
		customizers.forEach((c) -> c.customize(http));
		// @formatter:on
		return http.build();
	}


	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
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
	Customizer<HttpSecurity> passwordResetFilter(UserDetailsPasswordService passwords, ChangePasswordAdviceRepository advice) {
		ChangePasswordProcessingFilter processing = new ChangePasswordProcessingFilter(passwords);
		processing.setChangePasswordAdviceRepository(advice);
		ChangePasswordAdvisingFilter advising = new ChangePasswordAdvisingFilter();
		advising.setChangePasswordAdviceRepository(advice);
		return (http) -> http
			.addFilterBefore(new DefaultChangePasswordPageGeneratingFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(processing, UsernamePasswordAuthenticationFilter.class)
			// TODO: does this prevent logout?
			.addFilterBefore(advising, UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	Customizer<HttpSecurity> usernamePasswordFilter(AuthenticationManager authenticationManager, ChangePasswordAdviceRepository advice) {
		PasswordCheckingUsernamePasswordAuthenticationFilter filter =
			new PasswordCheckingUsernamePasswordAuthenticationFilter(authenticationManager);
		filter.setChangePasswordAdviceRepository(advice);
		return (http) -> http.addFilterAt(filter, UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	ChangePasswordAdviceRepository changePasswordAdviceRepository(ChangePasswordAdviceService advice) {
		HttpSessionChangePasswordAdviceRepository repository = new HttpSessionChangePasswordAdviceRepository();
		repository.setChangePasswordAdviceService(advice);
		return repository;
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
			new ChangeLengthPasswordAdvisor(12, 72),
			new ChangePasswordServiceAdvisor(passwords)));
	}

}
