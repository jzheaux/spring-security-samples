package org.example.compromisedpasswordchecker;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.CompositeUpdatePasswordAdvisor;
import org.springframework.security.authentication.password.PasswordAction;
import org.springframework.security.authentication.password.PasswordAdvice;
import org.springframework.security.authentication.password.RepeatedPasswordAdvisor;
import org.springframework.security.authentication.password.UpdatePasswordAdvisor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.password.CompromisedPasswordAdvisor;
import org.springframework.security.web.authentication.password.HttpSessionPasswordAdviceRepository;
import org.springframework.security.web.authentication.password.PasswordAdviceRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
class ResetPasswordController {
    private final PasswordAdviceRepository passwordAdviceRepository =
        new HttpSessionPasswordAdviceRepository();

    private final UpdatePasswordAdvisor updatePasswordAdvisor = CompositeUpdatePasswordAdvisor.of(
        new RepeatedPasswordAdvisor(), new CompromisedPasswordAdvisor());

    private final PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private final InMemoryUserDetailsManager users;

    ResetPasswordController(InMemoryUserDetailsManager users) {
        this.users = users;
    }

    @GetMapping("/admin/require-change-password")
    String requireChange() {
        return "require-change-password";
    }

    @PostMapping("/admin/require-change-password")
    String postRequireChange(User user) {
        UserDetails details = this.users.loadUserByUsername(user.username());
        this.users.savePasswordAction(details, PasswordAction.MUST_CHANGE);
        return "index";
    }

    @GetMapping("/change-password")
    String change() {
        return "change-password";
    }

    @PostMapping("/change-password")
    String changePassword(Authentication authentication, Passwords passwords,
        HttpServletRequest request, HttpServletResponse response) throws Exception{
        if (!passwords.passwordsAreEqual()) {
            request.setAttribute("error", "The passwords don't match");
            return "change-password";
        }
        UserDetails user = this.users.loadUserByUsername(authentication.getName());
        PasswordAdvice advice = this.updatePasswordAdvisor.advise(user, user.getPassword(), passwords.updated());
        if (advice.getAction().equals(PasswordAction.ABSTAIN)) {
            String encoded = this.passwordEncoder.encode(passwords.updated());
            this.users.updatePassword(user, encoded);
            this.passwordAdviceRepository.removePasswordAdvice(request, response);
            request.getRequestDispatcher("/logout").forward(request, response);
            return null;
        }
        request.setAttribute("error", "The password fails because: " + advice);
        return "change-password";
    }


    record User(String username) {
    }

    record Passwords(String updated, String confirmed) {
        boolean passwordsAreEqual() {
            return this.updated.equals(this.confirmed);
        }
    }

}
