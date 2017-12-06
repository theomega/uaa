package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class PasswordChangeRequiredFilter extends OncePerRequestFilter {

    private final PasswordChangeRequiredCheck check;
    private final String redirectUri;
    private final AntPathRequestMatcher matcher;
    private final AntPathRequestMatcher completed = new AntPathRequestMatcher("/force_password_change_completed");
    private final RequestCache cache;

    public PasswordChangeRequiredFilter(PasswordChangeRequiredCheck check, String redirectUri, RequestCache cache) {
        this.check = check;
        this.redirectUri = redirectUri;
        matcher = new AntPathRequestMatcher(redirectUri);
        this.cache = cache;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isCompleted(request)) {
            SavedRequest savedRequest = cache.getRequest(request, response);
            if (savedRequest != null) {
                logger.debug("Redirecting request to " + savedRequest.getRedirectUrl());
                sendRedirect(savedRequest.getRedirectUrl(), request, response);
            } else {
                logger.debug("Redirecting request to /");
                sendRedirect("/", request, response);
            }
        } else if (check.needsPasswordReset() && !matcher.matches(request)) {
            cache.saveRequest(request, response);
            sendRedirect(redirectUri, request, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private boolean isCompleted(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && completed.matches(request)) {
            return true;
        }
        return false;
    }

    protected void sendRedirect(String redirectUrl, HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder url = new StringBuilder(
            redirectUrl.startsWith("/") ? request.getContextPath() : ""
        );
        url.append(redirectUrl);
        response.sendRedirect(url.toString());
    }
}
