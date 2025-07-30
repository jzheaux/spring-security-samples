package org.example.compromisedpasswordchecker;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvice.Action;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.ChangePasswordReasons;
import org.springframework.security.authentication.password.SimpleChangePasswordAdvice;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

class ChangeRepeatedPasswordAdvisor implements ChangePasswordAdvisor {

    private final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Override
    public ChangePasswordAdvice advise(UserDetails user, String password) {
        if (this.passwordEncoder.matches(password, user.getPassword())) {
            return new SimpleChangePasswordAdvice(Action.MUST_CHANGE, ChangePasswordReasons.REPEATED);
        }
        return ChangePasswordAdvice.abstain();
    }
}
