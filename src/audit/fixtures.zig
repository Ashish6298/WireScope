const std = @import("std");
const testing = std.testing;

/// Comprehensive HTTP fixture responses for defensive security auditing.
/// Hermetic testing covers every rule without live network dependency.
pub const FixtureId = enum {
    fully_hardened_https,
    missing_hsts_https,
    weak_hsts_short_maxage,
    weak_hsts_no_subdomains,
    hsts_on_http_insecure,
    missing_csp_html,
    weak_csp_unsafe_inline,
    weak_csp_unsafe_eval,
    weak_csp_wildcard,
    json_api_endpoint_no_csp,
    missing_nosniff,
    cookie_missing_secure,
    cookie_missing_httponly,
    cookie_missing_samesite,
    cookie_samesite_none_insecure,
    cookie_fully_hardened,
    http_plain_no_redirect,
    http_temporary_redirect,
    http_permanent_redirect_to_https,
    redirect_out_of_scope,
    redirect_loop,
    redirect_limit_exceeded,
    missing_framing_protection,
    server_version_disclosure,
    oversized_response,
};

pub const HTTP_200_HARDENED_HTTPS =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Server: wirescope-secure-gateway\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 64\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n" ++
    "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "X-Frame-Options: DENY\r\n" ++
    "Referrer-Policy: strict-origin-when-cross-origin\r\n" ++
    "Set-Cookie: __Host-session=a1b2c3d4e5; Secure; HttpOnly; SameSite=Strict; Path=/\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><head><title>Secure</title></head></html>";

pub const HTTP_200_MISSING_HSTS_HTTPS =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "X-Frame-Options: SAMEORIGIN\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>No HSTS</body></html>";

pub const HTTP_200_WEAK_HSTS_SHORT_MAXAGE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=3600; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Short HSTS</body></html>";

pub const HTTP_200_WEAK_HSTS_NO_SUBDOMAINS =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>No SubDomains</body></html>";

pub const HTTP_200_HSTS_ON_HTTP_INSECURE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Insecure HSTS</body></html>";

pub const HTTP_200_MISSING_CSP_HTML =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "X-Frame-Options: DENY\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Missing CSP</body></html>";

pub const HTTP_200_WEAK_CSP_UNSAFE_INLINE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Unsafe Inline</body></html>";

pub const HTTP_200_WEAK_CSP_UNSAFE_EVAL =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Unsafe Eval</body></html>";

pub const HTTP_200_WEAK_CSP_WILDCARD =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src *\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Wildcard CSP</body></html>";

pub const HTTP_200_JSON_API_ENDPOINT_NO_CSP =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: application/json; charset=utf-8\r\n" ++
    "Content-Length: 28\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "{\"status\":\"ok\",\"service\":\"api\"}";

pub const HTTP_200_MISSING_NOSNIFF =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>No Nosniff</body></html>";

pub const HTTP_200_COOKIE_MISSING_SECURE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Set-Cookie: user_auth=secret_token_123; HttpOnly; SameSite=Lax; Path=/\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Insecure Cookie</body></html>";

pub const HTTP_200_COOKIE_MISSING_HTTPONLY =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Set-Cookie: session_id=sess_abc987; Secure; SameSite=Strict; Path=/\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Missing HttpOnly</body></html>";

pub const HTTP_200_COOKIE_MISSING_SAMESITE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Set-Cookie: auth_token=jwt_xyz; Secure; HttpOnly; Path=/\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Missing SameSite</body></html>";

pub const HTTP_200_COOKIE_SAMESITE_NONE_INSECURE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Set-Cookie: tracker=tk_123; SameSite=None; Path=/\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>SameSite None Insecure</body></html>";

pub const HTTP_200_HTTP_PLAIN_NO_REDIRECT =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Plain HTTP No Redirect</body></html>";

pub const HTTP_302_HTTP_TEMPORARY_REDIRECT =
    "HTTP/1.1 302 Found\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Location: https://localhost:8443/login\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_301_HTTP_PERMANENT_REDIRECT =
    "HTTP/1.1 301 Moved Permanently\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Location: https://localhost:8443/\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_302_REDIRECT_OUT_OF_SCOPE =
    "HTTP/1.1 302 Found\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Location: https://unauthorized-evil.test/hijack\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_200_MISSING_FRAMING_PROTECTION =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Missing Framing</body></html>";

pub const HTTP_200_SERVER_VERSION_DISCLOSURE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Server: Apache/2.4.52 (Ubuntu) mod_ssl/2.4.52 OpenSSL/3.0.2\r\n" ++
    "X-Powered-By: PHP/8.1.2\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>Version Leak</body></html>";

pub const HTTP_OVERSIZED_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: application/octet-stream\r\n" ++
    "Content-Length: 10485760\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

test "fixtures: all defined responses have valid HTTP status lines" {
    const list = [_][]const u8{
        HTTP_200_HARDENED_HTTPS,
        HTTP_200_MISSING_HSTS_HTTPS,
        HTTP_200_WEAK_HSTS_SHORT_MAXAGE,
        HTTP_200_WEAK_HSTS_NO_SUBDOMAINS,
        HTTP_200_HSTS_ON_HTTP_INSECURE,
        HTTP_200_MISSING_CSP_HTML,
        HTTP_200_WEAK_CSP_UNSAFE_INLINE,
        HTTP_200_WEAK_CSP_UNSAFE_EVAL,
        HTTP_200_WEAK_CSP_WILDCARD,
        HTTP_200_JSON_API_ENDPOINT_NO_CSP,
        HTTP_200_MISSING_NOSNIFF,
        HTTP_200_COOKIE_MISSING_SECURE,
        HTTP_200_COOKIE_MISSING_HTTPONLY,
        HTTP_200_COOKIE_MISSING_SAMESITE,
        HTTP_200_COOKIE_SAMESITE_NONE_INSECURE,
        HTTP_200_HTTP_PLAIN_NO_REDIRECT,
        HTTP_302_HTTP_TEMPORARY_REDIRECT,
        HTTP_301_HTTP_PERMANENT_REDIRECT,
        HTTP_302_REDIRECT_OUT_OF_SCOPE,
        HTTP_200_MISSING_FRAMING_PROTECTION,
        HTTP_200_SERVER_VERSION_DISCLOSURE,
        HTTP_OVERSIZED_RESPONSE,
    };

    for (list) |resp| {
        try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 "));
    }
}
