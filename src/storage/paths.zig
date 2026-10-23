const std = @import("std");
const builtin = @import("builtin");
const schema = @import("schema.zig");
pub const StorageError = schema.StorageError;

/// Storage directory paths manager and resolver
pub const StoragePaths = struct {
    base_dir: []const u8,

    pub fn init(base_dir: []const u8) StoragePaths {
        return .{ .base_dir = base_dir };
    }

    /// Subdirectory for assessment profiles
    pub fn profilesDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "profiles" });
    }

    /// Subdirectory for assessment results
    pub fn assessmentsDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "assessments" });
    }

    /// Subdirectory for raw observations
    pub fn observationsDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "observations" });
    }

    /// Subdirectory for tracked defensive findings
    pub fn findingsDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "findings" });
    }

    /// Subdirectory for baseline snapshots
    pub fn baselinesDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "baselines" });
    }

    /// Subdirectory for report manifests
    pub fn manifestsDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "manifests" });
    }

    /// Subdirectory for isolated practice lab fixtures and state
    pub fn labDir(self: StoragePaths, allocator: std.mem.Allocator) ![]const u8 {
        return std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, "lab" });
    }

    /// Ensures the full storage directory hierarchy exists
    pub fn ensureDirectoriesExist(self: StoragePaths, allocator: std.mem.Allocator) !void {
        try std.fs.cwd().makePath(self.base_dir);

        const p = try self.profilesDir(allocator);
        defer allocator.free(p);
        try std.fs.cwd().makePath(p);

        const a = try self.assessmentsDir(allocator);
        defer allocator.free(a);
        try std.fs.cwd().makePath(a);

        const o = try self.observationsDir(allocator);
        defer allocator.free(o);
        try std.fs.cwd().makePath(o);

        const f = try self.findingsDir(allocator);
        defer allocator.free(f);
        try std.fs.cwd().makePath(f);

        const b = try self.baselinesDir(allocator);
        defer allocator.free(b);
        try std.fs.cwd().makePath(b);

        const m = try self.manifestsDir(allocator);
        defer allocator.free(m);
        try std.fs.cwd().makePath(m);
    }

    /// Enforces sandbox containment: rejects any path traversal attempting to escape
    /// the WireScope storage hierarchy (e.g. '../', '..\\', absolute root prefixes).
    pub fn validateContainedPath(self: StoragePaths, allocator: std.mem.Allocator, sub_dir: []const u8, file_name: []const u8) ![]const u8 {
        if (file_name.len == 0 or
            std.mem.indexOf(u8, file_name, "..") != null or
            std.mem.indexOfScalar(u8, file_name, '/') != null or
            std.mem.indexOfScalar(u8, file_name, '\\') != null or
            std.mem.indexOfScalar(u8, file_name, ':') != null)
        {
            return StorageError.PathTraversalEscape;
        }

        const full_sub_dir = try std.fs.path.join(allocator, &[_][]const u8{ self.base_dir, sub_dir });
        defer allocator.free(full_sub_dir);

        return try std.fs.path.join(allocator, &[_][]const u8{ full_sub_dir, file_name });
    }
};

/// Resolves the default storage directory per operating system:
/// - Windows: %LOCALAPPDATA%\wirescope or %USERPROFILE%\.wirescope
/// - Linux: $XDG_DATA_HOME/wirescope or ~/.local/share/wirescope
/// - macOS: ~/Library/Application Support/wirescope
pub fn resolveDefaultDataDir(allocator: std.mem.Allocator) ![]const u8 {
    switch (builtin.os.tag) {
        .windows => {
            if (std.process.getEnvVarOwned(allocator, "LOCALAPPDATA")) |lad| {
                defer allocator.free(lad);
                return std.fs.path.join(allocator, &[_][]const u8{ lad, "wirescope" });
            } else |_| {
                if (std.process.getEnvVarOwned(allocator, "USERPROFILE")) |up| {
                    defer allocator.free(up);
                    return std.fs.path.join(allocator, &[_][]const u8{ up, ".wirescope" });
                } else |_| {
                    return allocator.dupe(u8, ".wirescope");
                }
            }
        },
        .macos => {
            if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
                defer allocator.free(home);
                return std.fs.path.join(allocator, &[_][]const u8{ home, "Library", "Application Support", "wirescope" });
            } else |_| {
                return allocator.dupe(u8, ".wirescope");
            }
        },
        else => {
            if (std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME")) |xdg| {
                defer allocator.free(xdg);
                return std.fs.path.join(allocator, &[_][]const u8{ xdg, "wirescope" });
            } else |_| {
                if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
                    defer allocator.free(home);
                    return std.fs.path.join(allocator, &[_][]const u8{ home, ".local", "share", "wirescope" });
                } else |_| {
                    return allocator.dupe(u8, ".wirescope");
                }
            }
        },
    }
}
