package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class PasswordChangeRequiredCheck {

    public boolean needsPasswordReset() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null &&
            authentication instanceof UaaAuthentication &&
            ((UaaAuthentication)authentication).isRequiresPasswordChange() &&
            authentication.isAuthenticated();
    }
}
