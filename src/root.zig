const std = @import("std");
const testing = std.testing;

pub const core = @import("core/root.zig");
pub const platform = @import("platform/root.zig");
pub const probes = @import("probes/root.zig");
pub const assessment = @import("assessment/root.zig");
pub const policy = @import("policy/root.zig");
pub const storage = @import("storage/root.zig");
pub const reporting = @import("reporting/root.zig");
pub const lab = @import("lab/root.zig");
pub const recon = @import("recon/root.zig");
pub const audit = @import("audit/root.zig");

pub const version = core.Version.string;

test "wirescope library root exports all modules" {
    _ = core;
    _ = platform;
    _ = probes;
    _ = assessment;
    _ = policy;
    _ = storage;
    _ = reporting;
    _ = lab;
    _ = recon;
    _ = audit;
    try testing.expectEqualStrings("1.0.0", version);
}
