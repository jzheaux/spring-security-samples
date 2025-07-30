package org.example.compromisedpasswordchecker;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.DelegatingChangePasswordAdvisor;
import org.springframework.security.authentication.password.UserDetailsPasswordManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.ChangePasswordAdviceRepository;
import org.springframework.security.web.authentication.password.HttpSessionChangePasswordAdviceRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
class ResetPasswordController {
    private final ChangePasswordAdviceRepository changePasswordAdviceRepository =
        new HttpSessionChangePasswordAdviceRepository();

    private final ChangePasswordAdvisor changePasswordAdvisor = DelegatingChangePasswordAdvisor.of(
        new ChangeRepeatedPasswordAdvisor(), new ChangeCompromisedPasswordAdvisor());

    private final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private final InMemoryUserDetailsManager users;

    ResetPasswordController(InMemoryUserDetailsManager users) {
        this.users = users;
    }

    @GetMapping("/change-password")
    String change() {
        return "change-password";
    }

    @PostMapping("/change-password")
    String changePassword(Authentication authentication, ChangePassword changePassword,
        HttpServletRequest request, HttpServletResponse response) {
        if (!changePassword.passwordsAreEqual()) {
            request.setAttribute("error", "The passwords don't match");
            return "change-password";
        }
        UserDetails user = this.users.loadUserByUsername(authentication.getName());
        ChangePasswordAdvice advice = this.changePasswordAdvisor.advise(user, changePassword.newPassword);
        if (advice.getAction().equals(ChangePasswordAdvice.Action.ABSTAIN)) {
            String encoded = this.passwordEncoder.encode(changePassword.newPassword);
            this.users.updatePassword(user, encoded);
            this.changePasswordAdviceRepository.removePasswordAdvice(request, response);
            return "index";
        }
        request.setAttribute("error", "The password fails because: " + advice.getReasons());
        return "change-password";
    }

    record ChangePassword(String newPassword, String confirmPassword) {
        boolean passwordsAreEqual() {
            return newPassword.equals(confirmPassword);
        }
    }

}
