const std = @import("std");
const testing = std.testing;

pub const default_sensitive_patterns = [_][]const u8{
    "password",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer",
    "authorization",
};

/// Redacts sensitive keywords and potential credential values in diagnostic messages
pub fn redactSensitive(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var lower_buf = try allocator.alloc(u8, input.len);
    defer allocator.free(lower_buf);
    @memcpy(lower_buf, input);
    for (lower_buf) |*c| {
        c.* = std.ascii.toLower(c.*);
    }

    var i: usize = 0;
    while (i < input.len) {
        var matched = false;
        for (default_sensitive_patterns) |pat| {
            if (i + pat.len <= input.len and std.mem.eql(u8, lower_buf[i .. i + pat.len], pat)) {
                // Find delimiter (=, :, whitespace)
                var delim_idx = i + pat.len;
                while (delim_idx < input.len and (input[delim_idx] == ' ' or input[delim_idx] == '=' or input[delim_idx] == ':')) : (delim_idx += 1) {}
                // Redact value until next delimiter or end
                var val_end = delim_idx;
                while (val_end < input.len and input[val_end] != ' ' and input[val_end] != ',' and input[val_end] != '&' and input[val_end] != ';') : (val_end += 1) {}

                try result.appendSlice(input[i..delim_idx]);
                try result.appendSlice("[REDACTED]");
                i = val_end;
                matched = true;
                break;
            }
        }
        if (!matched) {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

test "redact sensitive keywords in diagnostic output" {
    const allocator = testing.allocator;

    const input = "Target connection failed with token=secret12345 and password: mySuperPassword!";
    const redacted = try redactSensitive(allocator, input);
    defer allocator.free(redacted);

    try testing.expect(std.mem.indexOf(u8, redacted, "secret12345") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "mySuperPassword!") == null);
    try testing.expect(std.mem.indexOf(u8, redacted, "[REDACTED]") != null);
}
