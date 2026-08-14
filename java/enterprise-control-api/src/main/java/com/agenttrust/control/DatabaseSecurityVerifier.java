package com.agenttrust.control;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public final class DatabaseSecurityVerifier implements InitializingBean {
    private final JdbcTemplate jdbc;
    private final ControlProperties properties;
    private final String databaseUrl;

    public DatabaseSecurityVerifier(JdbcTemplate jdbc, ControlProperties properties,
                                    @Value("${spring.datasource.url}") String databaseUrl) {
        this.jdbc = jdbc;
        this.properties = properties;
        this.databaseUrl = databaseUrl;
    }

    @Override
    public void afterPropertiesSet() {
        DatabasePosture posture = jdbc.queryForObject(
            "SELECT current_user, r.rolsuper, r.rolbypassrls, COALESCE(s.ssl, false), "
                + "current_setting('search_path'), current_schemas(true)::text "
                + "FROM pg_roles r LEFT JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() "
                + "WHERE r.rolname=current_user",
            (result, ignored) -> new DatabasePosture(result.getString(1), result.getBoolean(2),
                result.getBoolean(3), result.getBoolean(4), result.getString(5),
                result.getString(6)));
        if (posture == null || !properties.expectedDatabaseRole().equals(posture.role())
            || posture.superuser() || posture.bypassRls()
            || !"pg_catalog, public".equals(posture.searchPath())
            || !"{pg_catalog,public}".equals(posture.resolvedSchemas())
            || properties.databaseTlsRequired()
                && (!posture.tls() || !verifyFullJdbcUrl(databaseUrl))) {
            throw new IllegalStateException("CONTROL_DATABASE_POSTURE_DENIED");
        }
    }

    /**
     * pg_stat_ssl proves encryption, not server identity verification.  The PostgreSQL driver only
     * guarantees CA and hostname verification for sslmode=verify-full, so production refuses
     * ambiguous, duplicated, or custom-verifier JDBC parameters as well as an implicit root CA.
     */
    static boolean verifyFullJdbcUrl(String value) {
        if (value == null || !value.startsWith("jdbc:postgresql://")
            || value.indexOf('#') >= 0 || value.indexOf('@') >= 0) {
            return false;
        }
        int queryStart = value.indexOf('?');
        if (queryStart < 0 || queryStart == value.length() - 1) {
            return false;
        }
        Map<String, String> parameters = new HashMap<>();
        for (String item : value.substring(queryStart + 1).split("&", -1)) {
            int equals = item.indexOf('=');
            if (equals < 1) {
                return false;
            }
            String name = URLDecoder.decode(item.substring(0, equals), StandardCharsets.UTF_8)
                .toLowerCase(java.util.Locale.ROOT);
            String parameter = URLDecoder.decode(item.substring(equals + 1),
                StandardCharsets.UTF_8);
            if (parameters.putIfAbsent(name, parameter) != null) {
                return false;
            }
        }
        String rootCertificate = parameters.get("sslrootcert");
        if (!"verify-full".equals(parameters.get("sslmode"))
            || parameters.containsKey("sslfactory")
            || parameters.containsKey("sslfactoryarg")
            || parameters.containsKey("sslhostnameverifier")
            || !"-csearch_path=pg_catalog,public".equals(parameters.get("options"))
            || rootCertificate == null || rootCertificate.isBlank()) {
            return false;
        }
        try {
            Path root = Path.of(rootCertificate);
            return root.isAbsolute() && Files.isRegularFile(root) && Files.size(root) > 0
                && Files.size(root) <= 1024 * 1024;
        } catch (RuntimeException | java.io.IOException error) {
            return false;
        }
    }

    record DatabasePosture(String role, boolean superuser, boolean bypassRls, boolean tls,
                           String searchPath, String resolvedSchemas) {}
}
