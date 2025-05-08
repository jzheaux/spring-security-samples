package org.example.compromisedpasswordchecker;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

public final class ChangeCompromisedPasswordAdvisor implements ChangePasswordAdvisor {
	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	@Override
	public ChangePasswordAdvice advise(ChangePasswordAdviceRequest request) {
		return new Advice(this.pwned.check(request.password()));
	}

	private static final class Advice implements ChangePasswordAdvice {
		private final CompromisedPasswordDecision decision;
		private final Collection<ChangePasswordReason> reasons;

		public Advice(CompromisedPasswordDecision decision) {
			this.decision = decision;
			this.reasons = decision.isCompromised() ? List.of(ChangePasswordReason.COMPROMISED) : List.of();
		}

		@Override
		public Collection<ChangePasswordReason> getRequireChangeReasons() {
			return List.of();
		}

		@Override
		public Collection<ChangePasswordReason> getChangeReasons() {
			return this.reasons;
		}
	}
}
