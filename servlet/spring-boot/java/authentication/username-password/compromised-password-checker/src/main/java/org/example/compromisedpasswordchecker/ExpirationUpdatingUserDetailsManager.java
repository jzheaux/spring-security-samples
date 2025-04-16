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

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;

public class ExpirationUpdatingUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {
	private final UserDetailsManager users;

	public ExpirationUpdatingUserDetailsManager(UserDetailsManager users) {
		this.users = users;
	}

	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		UserDetails updated = User.withUsername(user.getUsername())
			.password(newPassword)
			.authorities(user.getAuthorities())
			.credentialsExpired(false).build();
		this.users.updateUser(updated);
		return updated;
	}

	@Override
	public void createUser(UserDetails user) {
		this.users.createUser(user);
	}

	@Override
	public void updateUser(UserDetails user) {
		this.users.updateUser(user);
	}

	@Override
	public void deleteUser(String username) {
		this.users.deleteUser(username);
	}

	@Override
	public void changePassword(String oldPassword, String newPassword) {
		this.users.changePassword(oldPassword, newPassword);
	}

	@Override
	public boolean userExists(String username) {
		return this.users.userExists(username);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.users.loadUserByUsername(username);
	}
}
