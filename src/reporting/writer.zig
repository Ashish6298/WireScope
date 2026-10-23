const std = @import("std");
const testing = std.testing;

pub const SafeWriteError = error{
    FileAlreadyExists,
    InvalidPath,
    OutOfMemory,
    DiskFull,
    AccessDenied,
} || std.fs.File.OpenError || std.fs.File.WriteError;

/// Safely writes report content to target_path with atomic write semantics
/// and overwrite prevention unless force is explicitly set to true.
pub fn safeWriteReportFile(
    allocator: std.mem.Allocator,
    target_path: []const u8,
    content: []const u8,
    force: bool,
) SafeWriteError!void {
    if (target_path.len == 0) return SafeWriteError.InvalidPath;

    // 1. Guard against accidental overwrite
    if (!force) {
        if (std.fs.cwd().access(target_path, .{})) |_| {
            return SafeWriteError.FileAlreadyExists;
        } else |_| {}
    }

    // 2. Prepare temporary atomic path
    const timestamp = std.time.milliTimestamp();
    const temp_filename = try std.fmt.allocPrint(allocator, "{s}.tmp.{d}", .{ target_path, timestamp });
    defer allocator.free(temp_filename);

    // 3. Create temporary file
    var temp_file = std.fs.cwd().createFile(temp_filename, .{
        .truncate = true,
        .read = false,
    }) catch |err| switch (err) {
        error.AccessDenied => return SafeWriteError.AccessDenied,
        else => return SafeWriteError.DiskFull,
    };

    var write_succeeded = false;
    defer {
        if (!write_succeeded) {
            std.fs.cwd().deleteFile(temp_filename) catch {};
        }
    }

    // 4. Write full content
    temp_file.writeAll(content) catch return SafeWriteError.DiskFull;

    // 5. Sync to storage medium
    temp_file.sync() catch {};
    temp_file.close();

    // 6. Rename/replace atomically
    // On Windows, if force is true and destination exists, rename might fail if not deleted first
    if (force) {
        std.fs.cwd().deleteFile(target_path) catch {};
    }

    std.fs.cwd().rename(temp_filename, target_path) catch |err| switch (err) {
        error.AccessDenied => return SafeWriteError.AccessDenied,
        else => return SafeWriteError.DiskFull,
    };

    write_succeeded = true;
}

test "safeWriteReportFile: creates file and prevents accidental overwrite without force" {
    const allocator = testing.allocator;

    const test_path = "test_safe_report_output.md";
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // 1. Initial write succeeds
    try safeWriteReportFile(allocator, test_path, "# Initial Report\n", false);

    // 2. Overwrite without force returns FileAlreadyExists
    const err = safeWriteReportFile(allocator, test_path, "# Overwrite Attempt\n", false);
    try testing.expectError(SafeWriteError.FileAlreadyExists, err);

    // 3. Overwrite with force succeeds
    try safeWriteReportFile(allocator, test_path, "# Forced Overwrite\n", true);

    const file = try std.fs.cwd().openFile(test_path, .{});
    defer file.close();
    const read_back = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(read_back);

    try testing.expectEqualStrings("# Forced Overwrite\n", read_back);
}
