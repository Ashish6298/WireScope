const std = @import("std");
const testing = std.testing;

pub const TEST_ROOT_CA_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDfzCCAmegAwIBAgIUdmj/DcVj+oVZIK0BEi1Ny4wNBYowDQYJKoZIhvcNAQEL
    \\BQAwRzEfMB0GA1UEAwwWV2lyZVNjb3BlIFRlc3QgUm9vdCBDQTEXMBUGA1UECgwO
    \\V2lyZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMB4XDTI2MTAyMjA1MjU0MFoXDTM2
    \\MTAxOTA1MjU0MFowRzEfMB0GA1UEAwwWV2lyZVNjb3BlIFRlc3QgUm9vdCBDQTEX
    \\MBUGA1UECgwOV2lyZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG
    \\9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoCq1pbVyl9kTADm9HDGeu0LXLFukusB9+FHv
    \\/lej4Jc/CqnvbG8SR6A2UkN1/7SV0yxTaL+sqEn+LWukIl6mgRTQo74yh7FRCgBX
    \\c3gYghwV4kTWHAtYc7d67cVkYDPlgBbBCQmHJ3j9xP1ndNFfRSw2DP8YyMjmrDhd
    \\7KtboKBUPrSBce6kLAzasDvTmuAGR+swo+HYsgKSUwg+Y2+hd8Axoeh1U5pXj4e4
    \\sfmWzCybH3G4cOSef0fZ9ym8VBx/SRLEQvDc6odZaEgohjikmfZXiWDls2166SGG
    \\ioL9MqyGj2pWKCh6+GXrx6ZFkmipGlLB4n62R8qYxLwFefuL1QIDAQABo2MwYTAd
    \\BgNVHQ4EFgQUmYjqFHs7rN1i3/HRi0DukIfitIowHwYDVR0jBBgwFoAUmYjqFHs7
    \\rN1i3/HRi0DukIfitIowDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
    \\DQYJKoZIhvcNAQELBQADggEBAA2afs921vqJQChGnIex/EY0P7yMj/Z9KBe6KPjb
    \\b+d4rPDoIO9AS6vjVscu2RZ4IFTijkb+9sAHfdIIDARd171SIIGTsOzqrOmnvxQY
    \\aK3OgnXPh/VCJO02wjdf3ye+Y7v+6lJQgS/zVtVnwZzupsb2cRmWhMB49H5XCR3m
    \\Dv8JPNnUKp6t51cGOVyh6ZldujKT3p0mCpQFmZbzHYgzXodLFOJGh8TyJSuIsupm
    \\t09JWfwOzFiCPrkv1jxmUON2fTIYEWjJoGgh4pf9dbz9zr0gA+n4UiCSU8nIEStz
    \\b0VM8Z0t9D5cRUz3syDcCxU5hqvEzb0lUjNjkEKuSrQDTmo=
    \\-----END CERTIFICATE-----
;

pub const TEST_VALID_SERVER_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDnDCCAoSgAwIBAgIUDEMsjys34k58+ewavc955FuO0WcwDQYJKoZIhvcNAQEL
    \\BQAwRzEfMB0GA1UEAwwWV2lyZVNjb3BlIFRlc3QgUm9vdCBDQTEXMBUGA1UECgwO
    \\V2lyZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMB4XDTI2MTAyMjA1MjU0MFoXDTM2
    \\MTAxOTA1MjU0MFowOjESMBAGA1UEAwwJbG9jYWxob3N0MRcwFQYDVQQKDA5XaXJl
    \\U2NvcGUgVGVzdDELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
    \\ggEKAoIBAQDe7joEIwn7HagCR3cP/T8mB9q7AtzFOHzmxJzqQ2jEOkoQ8U4a3AM7
    \\cXEgIDIG7mPsquZRzb+Us+zqzsPipDsttbrYlSljrwBMUjLcn1t1D5J1tM3kaFTb
    \\x1JdFuyHxZq8aHXqoWE9nW9iL4Qv5vuaVWJI0kqBZcxJHuAO+Sbmanmu1hUtuM2Q
    \\BWmlU1uLxlJJfTlw7Iv5T7sWLdq2sxpO+icJlp8Ak8a9m6bxeKz2cjsubY6RtmTQ
    \\uanaVGqmP+aH2mcFmI2MHsD6gG5hIMZDwLC7r546guwcgYSTw2VrmFl8wGkwrrZc
    \\Y3x9FREpMwjomAVCIBtIiPhElKotOW45AgMBAAGjgYwwgYkwGgYDVR0RBBMwEYIJ
    \\bG9jYWxob3N0hwR/AAABMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQM
    \\MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBQrvYCyy/5ODTkm/yfkxFBtnocs+jAfBgNV
    \\HSMEGDAWgBSZiOoUezus3WLf8dGLQO6Qh+K0ijANBgkqhkiG9w0BAQsFAAOCAQEA
    \\QjoMWyKx4eJkeZ5MFZ8HM6PL7JaToEqKYMgBy6Q2ya5bhH3FV5GdFWo/zPYTFoEp
    \\flm3UONv18LG0f+hhgcw4h679JKBtHLeENvMYJXBy01EWVtx0gN6683RuHMVJNJ+
    \\AYYy56uSR0C1upExY07Wo5bfqm5zjy3+RIxbKjjj6gQ13UkmrGqx1JoFE4Jw7wgv
    \\uHKrm4lImsJnFG/YzOL1kjN7poNuSebe5CLHi7TAdvw6ryZWUrJ4BYIrR5qpWLtx
    \\PAOsLwGq8VETEtCn5iWTowuJbC9yn5lqFpT3dv+Qus+HlEKC6/qGcKI3HWX3IqNp
    \\aaTTxsYK2E+qRQn9zLc4GQ==
    \\-----END CERTIFICATE-----
;

pub const TEST_MISMATCH_SERVER_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDmDCCAoCgAwIBAgIUDEMsjys34k58+ewavc955FuO0WgwDQYJKoZIhvcNAQEL
    \\BQAwRzEfMB0GA1UEAwwWV2lyZVNjb3BlIFRlc3QgUm9vdCBDQTEXMBUGA1UECgwO
    \\V2lyZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMB4XDTI2MTAyMjA1MjU0MFoXDTM2
    \\MTAxOTA1MjU0MFowOzETMBEGA1UEAwwKb3RoZXIudGVzdDEXMBUGA1UECgwOV2ly
    \\ZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
    \\MIIBCgKCAQEAsIdcTUwnpdANGdsyWvDMrrMsLW+qIbrAjwNun10wyV1ObJze1I/W
    \\dAbcqHkUvpHJO7Urp3m0LbWMy0pk/D3pOYupjySfdXdCorC6CRoho46EXahIULfV
    \\b5vFMz7uC9Qds+GqBhYefFyHBddWCt7zHp3mitu21FuKg+BRtMsl64kToNRi3x1N
    \\IlXvPPwY490zJ0Tz5UGzUoo0z7tGzDSeIr3fHuR8JX0FBvaA1cpX7KPmJlXWkkfw
    \\Dno8EDBHzidv2cEo1EMtQpOheTF5fPZtqjdQFmhgfl0aphhh6f1isScj0HwtdpdM
    \\QL+Sv53Suf6WvdCS+pLQrDYQ/Ubfe90KIwIDAQABo4GHMIGEMBUGA1UdEQQOMAyC
    \\Cm90aGVyLnRlc3QwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwEwYDVR0lBAwwCgYI
    \\KwYBBQUHAwEwHQYDVR0OBBYEFCjN7+4Rgl9jLkUwICMa0ut4hDRJMB8GA1UdIwQY
    \\MBaAFJmI6hR7O6zdYt/x0YtA7pCH4rSKMA0GCSqGSIb3DQEBCwUAA4IBAQCPZgDj
    \\xlSQkix6mqxx6j7mFnIh7V85PjA+CJ+oqFxN0DS5J7AT80chOx+hvWOehRMFZsWK
    \\CyhWefI2xTa8RoaaCsob8PgLPG/8EhHKp9nDlKGzjl1i+DcOGl+YLcw6geh+7aip
    \\Gb4qTO45tK6ccl72B0CTmw54q8QELU2o+SPm4HNwsPYDfKR0uSaqbLfEVn2c51yb
    \\3x/xWIsbwDvDzVatL7mE2rPkWLZik1z9In4CkxFjoNYwtVurxmowz6zbmGIzwxOe
    \\CIBceMOP83Udrd12XeQmBGX3dbr+eSS73foj5Nym8dYRUktziga8/nic9fb4T/Lz
    \\UzDcoS8ihVmIVXBi
    \\-----END CERTIFICATE-----
;

pub const TEST_ROGUE_CA_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDczCCAlugAwIBAgIUIRIwyw8UIu538kuaR9VF9I2rHwEwDQYJKoZIhvcNAQEL
    \\BQAwSTEgMB4GA1UEAwwXV2lyZVNjb3BlIFRlc3QgUm9ndWUgQ0ExGDAWBgNVBAoM
    \\D1dpcmVTY29wZSBSb2d1ZTELMAkGA1UEBhMCVVMwHhcNMjYxMDIyMDUyNTQwWhcN
    \\MzYxMDE5MDUyNTQwWjBJMSAwHgYDVQQDDBdXaXJlU2NvcGUgUm9ndWUgUm9vdCBD
    \\QTEYMBYGA1UECgwPV2lyZVNjb3BlIFJvZ3VlMQswCQYDVQQGEwJVUzCCASIwDQYJ
    \\KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMOToyic8TrsY4oCya9JROxZvrKUjy6D
    \\mYBH4V4ZprwUqoMa+fmDZa94xNwFVtCQ0uqscZ2HG1pS1LTZZPw06r9NXOglN9wr
    \\MtrwM4yD2L8QctYM8B+TPOeevGSK0sNG1WOfas7uOuXFmPtsB/wVqfoIZocm9M/S
    \\M8ywh7bj7nbkwPHi9y1jhEtHrCGBtcHzfzqsnIfEqUsO2PnSKpQa6/Ex6Ir4g4rc
    \\FV+zOnbEajjCm1PEMeESsAVcMqxE2CKyxGKbvWdBtf4uUQZ78c24kUIMwg8CCy3T
    \\78HKg7sRcD0mkbGfXmicsVngF/faEDTXEtIV9SwJwXSdQo7uQdM+jcMCAwEAAaNT
    \\MFEwHQYDVR0OBBYEFGFfa3Uw7VStDnHSBYJHEUfPOcN4MB8GA1UdIwQYMBaAFGFf
    \\a3Uw7VStDnHSBYJHEUfPOcN4MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
    \\BQADggEBAIOkH5l16RZxYkrdslINDh86THfCK4EWBVv9+R2d3bgq4WgLI1CiIy/H
    \\kZ0RcYXx92twSzA+UQ8tjsZ13RFCeT3YtsRdp6qIWOi7YCnIeNCOwYpNEDFWIZMg
    \\7cESkPdXfErk5DSchHITmYOHerKC/1fyOtIcwC1vsZF9Rdg4okV9RqJS2Aw584Gs
    \\FpjkB2H7utUuE8TOlZhW0x1QymWeyjI7hCWxLZHcYVk1cEFuJAaM+wQJXHLlvtCq
    \\Iw3ujkdUU9mkFv8eXcSta4wBiF5GsKBp/US2U5WyRWElAre+H47EScgLTZ7QDU21
    \\JPC313ARzyXplm8aTQ5CEdaf8c2djJ4=
    \\-----END CERTIFICATE-----
;

pub const TEST_UNTRUSTED_SERVER_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDozCCAougAwIBAgIUWCubq0cISjd2GNai6Bs1fvnNGTQwDQYJKoZIhvcNAQEL
    \\BQAwSTEgMB4GA1UEAwwXV2lyZVNjb3BlIFJvZ3VlIFJvb3QgQ0ExGDAWBgNVBAoM
    \\D1dpcmVTY29wZSBSb2d1ZTELMAkGA1UEBhMCVVMwHhcNMjYxMDIyMDUyNTQxWhcN
    \\MzYxMDE5MDUyNTQxWjA/MRIwEAYDVQQDDAlsb2NhbGhvc3QxHDAaBgNVBAoME1dp
    \\cmVTY29wZSBVbnRydXN0ZWQxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEF
    \\AAOCAQ8AMIIBCgKCAQEA15CJTFD+9qzGlrPwmvifMzPchRw/zFaph+jF2TzFkaty
    \\GEHBf9KcC8DvNvE0pGtgPoZVb4g1xHcaQZKC42B+0qwWuLJRacnoQ906t70bHuy6
    \\1rCN9T0CNVdnEVqLxn4HeepOttX4FN/VDcPxecObQHqp8FNNYsG5RRSiyvLe9L0W
    \\nEOsDmrwf4A9qLdSBpGQxJTNHxAzM+oUBPXlSikxmreQK1ww/hCVOJE42rDH3Yuk
    \\M20L2pUdMKv0zyEQKnIrQ9QyUSbFdTBksdfJcNv+UeRNGFTRQW3P1MToT8qI6BUR
    \\hrLHD5YFMxnAjqmk4nFGe9WbJQYyZWhQ60zciVokJwIDAQABo4GMMIGJMBoGA1Ud
    \\EQQTMBGCCWxvY2FsaG9zdIcEfwAAATAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAT
    \\BgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUxWzTlSowdxbGVRr9E9s0DSf9
    \\EHAwHwYDVR0jBBgwFoAUYV9rdTDtVK0OcdIFgkcRR885w3gwDQYJKoZIhvcNAQEL
    \\BQADggEBAFOsRSUymxV2aoTeWEVkpbVTBe5RbOyZlDlv8ZaT3P+A25a/7Q4Xtv5B
    \\U1x8ez9SZgYU/U6f+oDRSCRDIwJ0km0vmKFH0T5lN2CxwiO/761iiR7cesnrpTm1
    \\JpWVg61Fw7PnVnm9heiRnmIFi6Gfo2RnYLJYVT1tlcq6x0vgrxgX4MAJsQahIOHu
    \\wxjpgNR+ZSGd/j7cX1swYFcZ6AJdERUcLC/XcpPSDUAz1lVza5vKH0a1YEoYGuP5
    \\8AwgATc5fxTLYzR9TmlY0dPiRBZZz75N8mwRUS/6ToWKX4uBQn2dj/inEPjwtSvu
    \\EQiKxIQ6hDT8zWwNPn1b68oUBPhc9iQ=
    \\-----END CERTIFICATE-----
;

pub const TEST_BADSIG_SERVER_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDnDCCAoSgAwIBAgIUDEMsjys34k58+ewavc955FuO0WowDQYJKoZIhvcNAQEL
    \\BQAwRzEfMB0GA1UEAwwWV2lyZVNjb3BlIFRlc3QgUm9vdCBDQTEXMBUGA1UECgwO
    \\V2lyZVNjb3BlIFRlc3QxCzAJBgNVBAYTAlVTMB4XDTI2MTAyMjA1MjYzMloXDTM2
    \\MTAxOTA1MjYzMlowOjESMBAGA1UEAwwJbG9jYWxob3N0MRcwFQYDVQQKDA5XaXJl
    \\U2NvcGUgVGVzdDELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
    \\ggEKAoIBAQDe7joEIwn7HagCR3cP/T8mB9q7AtzFOHzmxJzqQ2jEOkoQ8U4a3AM7
    \\cXEgIDIG7mPsquZRzb+Us+zqzsPipDsttbrYlSljrwBMUjLcn1t1D5J1tM3kaFTb
    \\x1JdFuyHxZq8aHXqoWE9nW9iL4Qv5vuaVWJI0kqBZcxJHuAO+Sbmanmu1hUtuM2Q
    \\BWmlU1uLxlJJfTlw7Iv5T7sWLdq2sxpO+icJlp8Ak8a9m6bxeKz2cjsubY6RtmTQ
    \\uanaVGqmP+aH2mcFmI2MHsD6gG5hIMZDwLC7r546guwcgYSTw2VrmFl8wGkwrrZc
    \\Y3x9FREpMwjomAVCIBtIiPhElKotOW45AgMBAAGjgYwwgYkwGgYDVR0RBBMwEYIJ
    \\bG9jYWxob3N0hwR/AAABMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQM
    \\MAoGCCsGAQUFBwMBMB0GA1UdDgQWBBQrvYCyy/5ODTkm/yfkxFBtnocs+jAfBgNV
    \\HSMEGDAWgBSZiOoUezus3WLf8dGLQO6Qh+K0ijANBgkqhkiG9w0BAQsFAAOCAQEA
    \\JB3+wAc/V4Zu29SUZCsXKyjYl/EbmFD4QbeZAtwk88gTLyA1w/2+VYD565/srnuo
    \\yXvjz8Ze+N0s7XhqhLz8Ehzg+uz3wFsuzRgt7XsItinRsnQHYIdzu3PQrVdBHio7
    \\WqufTR7VSo57f/Yv6pnELLCvHrdNl51kOb8y7CZyAcA3jiVOguxq8VkYqp8Crt4Q
    \\FBI8BqfLo5CuRBqW0WogWaEwyg4nyoUP5KXc+1hgqFTtANsNzM0l2wbsVlsYYXKe
    \\4UR6luf84eesIzFvwhg1gXryBwV/8qRVkziHIfwJibRn67HF+F5OmKuEvEzV4+BK
    \\g/RFbbI0AR9E+muccuiktQ==
    \\-----END CERTIFICATE-----
;

/// Adds certificates encoded as PEM into an in-memory Certificate.Bundle
pub fn addPemToBundle(bundle: *std.crypto.Certificate.Bundle, allocator: std.mem.Allocator, pem_bytes: []const u8, now_sec: i64) !void {
    const base64_dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    var start_index: usize = 0;

    while (std.mem.indexOfPos(u8, pem_bytes, start_index, begin_marker)) |begin_start| {
        const cert_start = begin_start + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, pem_bytes, cert_start, end_marker) orelse return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const b64 = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");

        const upper_bound = b64.len / 4 * 3 + 4;
        try bundle.bytes.ensureUnusedCapacity(allocator, upper_bound);
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        const dest = bundle.bytes.allocatedSlice()[decoded_start..];
        const written = try base64_dec.decode(dest, b64);
        bundle.bytes.items.len += written;
        try bundle.parseCert(allocator, decoded_start, now_sec);
    }
}

pub const ParsedPemCert = struct {
    bytes: []u8,
    cert: std.crypto.Certificate.Parsed,

    pub fn deinit(self: *ParsedPemCert, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

/// Parses the first certificate in a PEM string into a Certificate.Parsed struct
pub fn parseFirstPemCert(allocator: std.mem.Allocator, pem_bytes: []const u8) !ParsedPemCert {
    const base64_dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin_start = std.mem.indexOf(u8, pem_bytes, begin_marker) orelse return error.NoCertificateFound;
    const cert_start = begin_start + begin_marker.len;
    const cert_end = std.mem.indexOfPos(u8, pem_bytes, cert_start, end_marker) orelse return error.MissingEndCertificateMarker;
    const b64 = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");

    const upper_bound = b64.len / 4 * 3 + 4;
    const dest = try allocator.alloc(u8, upper_bound);
    errdefer allocator.free(dest);
    const written = try base64_dec.decode(dest, b64);

    const c = std.crypto.Certificate{ .buffer = dest[0..written], .index = 0 };
    const parsed = try std.crypto.Certificate.parse(c);
    return .{ .bytes = dest, .cert = parsed };
}

test "tls fixtures validation test" {
    const now_sec = std.time.timestamp();
    var bundle = std.crypto.Certificate.Bundle{};
    defer bundle.deinit(testing.allocator);
    try addPemToBundle(&bundle, testing.allocator, TEST_ROOT_CA_PEM, now_sec);
    try testing.expectEqual(@as(usize, 1), bundle.map.count());

    var valid = try parseFirstPemCert(testing.allocator, TEST_VALID_SERVER_PEM);
    defer valid.deinit(testing.allocator);
    try testing.expectEqualStrings("localhost", valid.cert.commonName());
    try valid.cert.verifyHostName("localhost");
    try bundle.verify(valid.cert, now_sec);

    var mismatch = try parseFirstPemCert(testing.allocator, TEST_MISMATCH_SERVER_PEM);
    defer mismatch.deinit(testing.allocator);
    try testing.expectError(error.CertificateHostMismatch, mismatch.cert.verifyHostName("localhost"));

    var untrusted = try parseFirstPemCert(testing.allocator, TEST_UNTRUSTED_SERVER_PEM);
    defer untrusted.deinit(testing.allocator);
    try testing.expectError(error.CertificateIssuerNotFound, bundle.verify(untrusted.cert, now_sec));

    var badsig = try parseFirstPemCert(testing.allocator, TEST_BADSIG_SERVER_PEM);
    defer badsig.deinit(testing.allocator);
    try testing.expectError(error.CertificateSignatureInvalid, bundle.verify(badsig.cert, now_sec));
}
