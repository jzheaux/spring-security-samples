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

package org.example.compromisedpasswordchecker;

import org.springframework.context.ApplicationContext;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

public final class PasswordManagementConfigurer<H extends HttpSecurityBuilder<H>>
	extends AbstractHttpConfigurer<PasswordManagementConfigurer<H>, H> {

	private final ApplicationContext context;

	public PasswordManagementConfigurer(ApplicationContext context) {
		this.context = context;
	}

	private String changePasswordUrl;

	private String changePasswordProcessingUrl = ChangePasswordProcessingFilter.DEFAULT_PASSWORD_CHANGE_PROCESSING_URL;

	private ChangePasswordAdviceRepository changePasswordAdviceRepository;

	private ChangePasswordAdvisor changePasswordAdvisor;

	private ChangePasswordAdviceHandler changePasswordAdviceHandler;

	private UserDetailsPasswordService userDetailsPasswordService;

	public PasswordManagementConfigurer<H> changePasswordProcessingUrl(String changePasswordProcessingUrl) {
		this.changePasswordProcessingUrl = changePasswordProcessingUrl;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordUrl(String changePasswordUrl) {
		this.changePasswordUrl = changePasswordUrl;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdvisor(ChangePasswordAdvisor changePasswordAdvisor) {
		this.changePasswordAdvisor = changePasswordAdvisor;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdviceHandler(ChangePasswordAdviceHandler changePasswordAdviceHandler) {
		this.changePasswordAdviceHandler = changePasswordAdviceHandler;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordService(UserDetailsPasswordService changePasswordService) {
		this.userDetailsPasswordService = changePasswordService;
		return this;
	}

	@Override
	public void init(H builder) throws Exception {
		builder.setSharedObject(ChangePasswordAdviceRepository.class, this.changePasswordAdviceRepository);
		builder.setSharedObject(ChangePasswordAdvisor.class, this.changePasswordAdvisor);
	}

	@Override
	public void configure(H http) throws Exception {
		PasswordEncoder passwordEncoder = this.context.getBeanProvider(PasswordEncoder.class).getIfUnique(
			PasswordEncoderFactories::createDelegatingPasswordEncoder);

		ChangePasswordAdviceHandler changePasswordAdviceHandler = (this.changePasswordAdviceHandler != null) ?
			this.changePasswordAdviceHandler :
			this.context.getBeanProvider(ChangePasswordAdviceHandler.class)
				.getIfUnique(() -> new SimpleChangePasswordAdviceHandler(this.changePasswordUrl));

		ChangePasswordAdviceRepository changePasswordAdviceRepository = (this.changePasswordAdviceRepository != null) ?
			this.changePasswordAdviceRepository :
			this.context.getBeanProvider(ChangePasswordAdviceRepository.class)
				.getIfUnique(HttpSessionChangePasswordAdviceRepository::new);

		ChangePasswordAdvisor changePasswordAdvisor = (this.changePasswordAdvisor != null) ?
			this.changePasswordAdvisor :
			this.context.getBeanProvider(ChangePasswordAdvisor.class)
				.getIfUnique(ChangeCompromisedPasswordAdvisor::new);

		UserDetailsPasswordService passwordService = (this.userDetailsPasswordService == null) ?
			this.context.getBean(UserDetailsPasswordService.class) : this.userDetailsPasswordService;

		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		PasswordCheckingUsernamePasswordAuthenticationFilter login = new PasswordCheckingUsernamePasswordAuthenticationFilter(authenticationManager);
		login.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
		login.setChangePasswordAdvisor(changePasswordAdvisor);
		http.addFilterBefore(login, UsernamePasswordAuthenticationFilter.class);

		if (this.changePasswordUrl == null) {
			DefaultChangePasswordPageGeneratingFilter page = new DefaultChangePasswordPageGeneratingFilter();
			http.addFilterBefore(page, UsernamePasswordAuthenticationFilter.class);
		}

		ChangePasswordProcessingFilter processing = new ChangePasswordProcessingFilter(passwordService);
		processing.setRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(this.changePasswordProcessingUrl));
		processing.setChangePasswordAdvisor(changePasswordAdvisor);
		processing.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
		processing.setPasswordEncoder(passwordEncoder);
		http.addFilterBefore(processing, UsernamePasswordAuthenticationFilter.class);

		ChangePasswordAdvisingFilter advising = new ChangePasswordAdvisingFilter();
		advising.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
		advising.setChangePasswordAdviceHandler(changePasswordAdviceHandler);
			// TODO: does this prevent logout?
		http.addFilterBefore(advising, UsernamePasswordAuthenticationFilter.class);
	}
}
