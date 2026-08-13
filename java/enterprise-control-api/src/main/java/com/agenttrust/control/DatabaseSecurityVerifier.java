package com.agenttrust.control;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public final class DatabaseSecurityVerifier implements InitializingBean {
    private final JdbcTemplate jdbc;
    private final ControlProperties properties;

    public DatabaseSecurityVerifier(JdbcTemplate jdbc, ControlProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    @Override
    public void afterPropertiesSet() {
        DatabasePosture posture = jdbc.queryForObject(
            "SELECT r.rolsuper, r.rolbypassrls, COALESCE(s.ssl, false) FROM pg_roles r LEFT JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=current_user",
            (result, ignored) -> new DatabasePosture(result.getBoolean(1), result.getBoolean(2),
                result.getBoolean(3)));
        if (posture == null || posture.superuser() || posture.bypassRls()
            || properties.databaseTlsRequired() && !posture.tls()) {
            throw new IllegalStateException("CONTROL_DATABASE_POSTURE_DENIED");
        }
    }

    record DatabasePosture(boolean superuser, boolean bypassRls, boolean tls) {}
}
