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

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@RequestMapping("/admin")
@Controller
public class AdminController {
	private final UserDetailsService users;
	private final ChangePasswordService passwords;

	public AdminController(UserDetailsService users, ChangePasswordService passwords) {
		this.users = users;
		this.passwords = passwords;
	}

	@GetMapping("/passwords/requireChange")
	public String requireChangePassword() {
		return "require-change-password";
	}

	@PostMapping("/passwords/requireChange")
	public ModelAndView requireChangePassword(@RequestParam("username") String username) {
		UserDetails user = this.users.loadUserByUsername(username);
		if (user == null) {
			return new ModelAndView("require-change-password", Map.of("status", "User not found :("));
		}
		this.passwords.savePasswordAdvice(user, ChangePasswordAdvice.require(ChangePasswordReason.EXPIRED));
		return new ModelAndView("require-change-password", Map.of("status", "Success!"));
	}
}
