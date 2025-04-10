package org.example.compromisedpasswordchecker;

import org.springframework.security.core.Authentication;

public interface PasswordResetAdvisor {
	PasswordAdvice check(Authentication authentication, String password);

	enum PasswordAdvice {
		KEEP, RESET, REQUIRE_RESET
	}
}

