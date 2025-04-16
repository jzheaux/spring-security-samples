package org.example.compromisedpasswordchecker;

import org.springframework.security.core.userdetails.UserDetails;

public interface PasswordAdvisor {
	PasswordAdvice advise(UserDetails user, String password);

	default PasswordAdvice advise(UserDetails user, String currentPassword, String newPassword) {
		if (currentPassword.equals(newPassword)) {
			return PasswordAdvice.REQUIRE_RESET;
		}
		return advise(user, newPassword);
	}

	enum PasswordAdvice {
		KEEP, RESET, REQUIRE_RESET
	}
}

