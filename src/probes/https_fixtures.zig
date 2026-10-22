const std = @import("std");
const testing = std.testing;

pub const FixtureType = enum {
    success_200,
    redirect_in_scope,
    redirect_out_of_scope,
    redirect_loop,
    redirect_limit_exceeded,
    oversized_response,
    invalid_certificate,
    timeout,
    cancelled,
};

pub const HTTP_200_OK_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Date: Thu, 22 Oct 2026 12:00:00 GMT\r\n" ++
    "Content-Type: text/html; charset=utf-8\r\n" ++
    "Content-Length: 48\r\n" ++
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
    "Content-Security-Policy: default-src 'self'\r\n" ++
    "X-Content-Type-Options: nosniff\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    "<!DOCTYPE html><html><body>WireScope</body></html>";

pub const HTTP_301_REDIRECT_IN_SCOPE_RESPONSE =
    "HTTP/1.1 301 Moved Permanently\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Location: https://localhost:443/destination\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_302_REDIRECT_OUT_OF_SCOPE_RESPONSE =
    "HTTP/1.1 302 Found\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Location: https://unauthorized-evil.test/login\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_302_LOOP_A_RESPONSE =
    "HTTP/1.1 302 Found\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Location: https://localhost:443/loop-b\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_302_LOOP_B_RESPONSE =
    "HTTP/1.1 302 Found\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Location: https://localhost:443/loop-a\r\n" ++
    "Content-Length: 0\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

pub const HTTP_OVERSIZED_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "Server: wirescope-test-server/1.0\r\n" ++
    "Content-Type: application/octet-stream\r\n" ++
    "Content-Length: 5000000\r\n" ++
    "Connection: close\r\n" ++
    "\r\n";

test "https fixtures content validation" {
    try testing.expect(std.mem.indexOf(u8, HTTP_200_OK_RESPONSE, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, HTTP_301_REDIRECT_IN_SCOPE_RESPONSE, "301 Moved Permanently") != null);
    try testing.expect(std.mem.indexOf(u8, HTTP_302_REDIRECT_OUT_OF_SCOPE_RESPONSE, "unauthorized-evil.test") != null);
}
