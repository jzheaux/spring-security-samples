package org.example.compromisedpasswordchecker;

import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

public class SimplePasswordResetAdvisor implements PasswordAdvisor {
	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	@Override
	public PasswordAdvice advise(UserDetails user, String password) {
		if (!user.isCredentialsNonExpired()) {
			return PasswordAdvice.REQUIRE_RESET;
		}
		if (this.pwned.check(password).isCompromised()) {
			return PasswordAdvice.RESET;
		}
		return PasswordAdvice.KEEP;
	}

}
