package org.example.compromisedpasswordchecker;

import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

public class ChangeCompromisedPasswordAdvisor implements ChangePasswordAdvisor {
	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	@Override
	public ChangePasswordAdvice advise(ChangePasswordAdviceRequest request) {
		return this.pwned.check(request.password()).isCompromised() ?
			DefaultChangePasswordAdvice.builder().recommend(ChangePasswordReason.COMPROMISED).build() :
			ChangePasswordAdvice.keep();
	}

}
