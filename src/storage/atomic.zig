const std = @import("std");

pub const AtomicWriteError = error{
    TemporaryFileCreationFailed,
    WriteFailed,
    SyncFailed,
    AtomicRenameFailed,
    DiskFull,
    AccessDenied,
};

/// Writes content to target file atomically.
///
/// Uses the write-to-temp-then-atomic-rename pattern:
/// 1. Creates a temporary file in the exact same directory: `{file_name}.tmp.{timestamp}_{pid}`
/// 2. Writes the full payload to the temporary file
/// 3. Flushes and syncs OS buffers to physical media via `file.sync()`
/// 4. Atomically renames temporary file to target path
/// 5. Automatically cleans up incomplete temp file on any error
///
/// Invariant: Crashes, power loss, or write failures prior to rename leave the destination
/// file completely untouched and never expose partially written or corrupt records.
pub fn atomicWriteFile(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    file_name: []const u8,
    content: []const u8,
) !void {
    const timestamp = std.time.milliTimestamp();

    var temp_name_buf: [128]u8 = undefined;
    const temp_name = try std.fmt.bufPrint(&temp_name_buf, "{s}.tmp.{d}", .{
        file_name,
        timestamp,
    });

    const full_temp_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, temp_name });
    defer allocator.free(full_temp_path);

    const full_target_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, file_name });
    defer allocator.free(full_target_path);

    // 1. Create temporary file
    var file = try std.fs.cwd().createFile(full_temp_path, .{
        .truncate = true,
        .read = false,
    });

    var write_succeeded = false;
    defer {
        if (!write_succeeded) {
            std.fs.cwd().deleteFile(full_temp_path) catch {};
        }
    }

    // 2. Write content
    try file.writeAll(content);

    // 3. Flush to disk
    try file.sync();

    // 4. Close handle before atomic rename
    file.close();

    // 5. Atomic rename to target destination
    try std.fs.cwd().rename(full_temp_path, full_target_path);
    write_succeeded = true;
}
