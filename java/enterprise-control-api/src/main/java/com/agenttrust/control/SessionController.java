package com.agenttrust.control;

import java.util.Set;
import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/session")
public final class SessionController {
    private final AuthenticatedPrincipalResolver principals;

    public SessionController(AuthenticatedPrincipalResolver principals) {
        this.principals = principals;
    }

    @GetMapping
    ResponseEntity<SessionView> session(Authentication authentication, CsrfToken csrfToken) {
        var principal = principals.resolve(authentication, null);
        var view = new SessionView("agenttrust.enterprise-session.v1", principal.tenantId(),
            principal.subject(), principal.roles(), principal.projectIds(), principal.approvalIds(),
            csrfToken.getHeaderName(), csrfToken.getToken());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(view);
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) {
        new org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler()
            .logout(request, response, authentication);
        response.addHeader("Set-Cookie",
            "SESSION=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None");
        response.addHeader("Set-Cookie",
            "__Host-XSRF-TOKEN=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=None");
        return ResponseEntity.noContent().build();
    }

    public record SessionView(String schemaVersion, UUID tenantId, String subject,
                              Set<String> roles, Set<String> projectIds, Set<String> approvalIds,
                              String csrfHeaderName, String csrfToken) {}
}
