const std = @import("std");
const testing = std.testing;
const synthetic = @import("synthetic.zig");
const scenario = @import("scenario.zig");
const service = @import("service.zig");
const atomic = @import("../storage/atomic.zig");

pub const LabManagerError = error{
    SandboxEscapeDetected,
    UnknownScenario,
    InvalidScenarioState,
    StateSerializationFailed,
    StateDeserializationFailed,
    ActiveScenarioAlreadyRunning,
    TargetPublicForbidden,
};

pub const ActiveLabState = struct {
    schema_version: u32 = 1,
    scenario_id: []const u8,
    scenario_title: []const u8,
    status: []const u8, // "ready", "active", "completed", "torn_down"
    bind_ip: []const u8,
    port: u16,
    target: []const u8,
    is_synthetic: bool = true,
    provenance: []const u8 = synthetic.SYNTHETIC_PROVENANCE,
    created_at_utc: i64,

    pub fn deinit(self: *ActiveLabState, allocator: std.mem.Allocator) void {
        allocator.free(self.scenario_id);
        allocator.free(self.scenario_title);
        allocator.free(self.status);
        allocator.free(self.bind_ip);
        allocator.free(self.target);
    }
};

pub const LabManager = struct {
    allocator: std.mem.Allocator,
    lab_dir: []const u8,
    active_service: ?*service.LabLoopbackService = null,

    pub fn init(allocator: std.mem.Allocator, lab_dir: []const u8) LabManager {
        return .{
            .allocator = allocator,
            .lab_dir = lab_dir,
            .active_service = null,
        };
    }

    /// Verifies that a target file path is strictly contained within the lab directory.
    /// Strictly rejects path traversal ('..'), absolute paths, or escaping symbols.
    pub fn validateSandboxPath(self: LabManager, filename: []const u8) !void {
        _ = self;
        if (filename.len == 0) return LabManagerError.SandboxEscapeDetected;

        // Path traversal patterns
        if (std.mem.indexOf(u8, filename, "..") != null or
            std.mem.indexOfScalar(u8, filename, ':') != null or
            std.mem.startsWith(u8, filename, "/") or
            std.mem.startsWith(u8, filename, "\\"))
        {
            return LabManagerError.SandboxEscapeDetected;
        }
    }

    pub fn setupScenario(self: *LabManager, scenario_id_str: []const u8) !ActiveLabState {
        // Ensure clean prior state (repeatable lifecycle)
        try self.cleanup();

        const scen = scenario.findScenario(scenario_id_str) orelse return LabManagerError.UnknownScenario;

        // Ensure lab sandbox directory exists
        try std.fs.cwd().makePath(self.lab_dir);

        var assigned_port: u16 = scen.default_port;
        const bind_ip = scen.default_bind_ip;

        if (scen.requires_service) {
            const service_kind: service.ServiceKind = switch (scen.id) {
                .http_security_header_violation => .http_mock_vulnerable,
                .remediation_verification => .http_mock_hardened,
                else => .raw_tcp,
            };

            const s = try service.LabLoopbackService.start(
                self.allocator,
                bind_ip,
                scen.default_port,
                service_kind,
            );
            self.active_service = s;
            assigned_port = s.port;
        }

        // Construct synthetic target string safely confined to loopback
        var target_buf: [256]u8 = undefined;
        const target_str = switch (scen.id) {
            .dns_failure => scen.target_synthetic,
            .tcp_refusal_timeout => blk: {
                // Closed loopback port for refusal testing
                break :blk try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{assigned_port});
            },
            .http_security_header_violation, .remediation_verification => blk: {
                break :blk try std.fmt.bufPrint(&target_buf, "http://127.0.0.1:{d}/", .{assigned_port});
            },
            .tls_cert_issues => blk: {
                break :blk try std.fmt.bufPrint(&target_buf, "https://127.0.0.1:{d}/", .{assigned_port});
            },
            else => blk: {
                break :blk try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{assigned_port});
            },
        };

        // Assert target safety: never public
        try synthetic.validateLabTarget(target_str);

        const now = std.time.timestamp();

        // Write active_state.json atomically
        var state_json_buf: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&state_json_buf);
        const writer = fbs.writer();

        try writer.print(
            \\{{
            \\  "schema_version": 1,
            \\  "scenario_id": "{s}",
            \\  "scenario_title": "{s}",
            \\  "status": "ready",
            \\  "bind_ip": "{s}",
            \\  "port": {d},
            \\  "target": "{s}",
            \\  "is_synthetic": true,
            \\  "provenance": "{s}",
            \\  "created_at_utc": {d}
            \\}}
            \\
        , .{
            scen.id_str,
            scen.title,
            bind_ip,
            assigned_port,
            target_str,
            synthetic.SYNTHETIC_PROVENANCE,
            now,
        });

        try self.validateSandboxPath("active_state.json");
        try atomic.atomicWriteFile(
            self.allocator,
            self.lab_dir,
            "active_state.json",
            fbs.getWritten(),
        );

        return ActiveLabState{
            .schema_version = 1,
            .scenario_id = try self.allocator.dupe(u8, scen.id_str),
            .scenario_title = try self.allocator.dupe(u8, scen.title),
            .status = try self.allocator.dupe(u8, "ready"),
            .bind_ip = try self.allocator.dupe(u8, bind_ip),
            .port = assigned_port,
            .target = try self.allocator.dupe(u8, target_str),
            .is_synthetic = true,
            .provenance = synthetic.SYNTHETIC_PROVENANCE,
            .created_at_utc = now,
        };
    }

    pub fn getStatus(self: LabManager) !?ActiveLabState {
        const state_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.lab_dir, "active_state.json" });
        defer self.allocator.free(state_path);

        const file = std.fs.cwd().openFile(state_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 16 * 1024);
        defer self.allocator.free(content);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch {
            return LabManagerError.StateDeserializationFailed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;
        const scen_id = obj.get("scenario_id").?.string;
        const scen_title = obj.get("scenario_title").?.string;
        const status = obj.get("status").?.string;
        const bind_ip = obj.get("bind_ip").?.string;
        const port: u16 = @intCast(obj.get("port").?.integer);
        const target = obj.get("target").?.string;
        const created_at = obj.get("created_at_utc").?.integer;

        return ActiveLabState{
            .schema_version = 1,
            .scenario_id = try self.allocator.dupe(u8, scen_id),
            .scenario_title = try self.allocator.dupe(u8, scen_title),
            .status = try self.allocator.dupe(u8, status),
            .bind_ip = try self.allocator.dupe(u8, bind_ip),
            .port = port,
            .target = try self.allocator.dupe(u8, target),
            .is_synthetic = true,
            .provenance = synthetic.SYNTHETIC_PROVENANCE,
            .created_at_utc = created_at,
        };
    }

    pub fn resetScenario(self: *LabManager) !ActiveLabState {
        const cur = try self.getStatus();
        if (cur) |c| {
            var state = c;
            defer state.deinit(self.allocator);
            return try self.setupScenario(state.scenario_id);
        } else {
            return LabManagerError.InvalidScenarioState;
        }
    }

    pub fn cleanup(self: *LabManager) !void {
        // 1. Stop active loopback service
        if (self.active_service) |s| {
            s.stop();
            self.active_service = null;
        }

        // 2. Safely remove active_state.json within sandbox
        try self.validateSandboxPath("active_state.json");
        const state_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.lab_dir, "active_state.json" });
        defer self.allocator.free(state_path);

        std.fs.cwd().deleteFile(state_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
};

test "lab manager: sandbox prevents escaping paths" {
    const mgr = LabManager.init(testing.allocator, "data/lab_test_sandbox");
    try testing.expectError(LabManagerError.SandboxEscapeDetected, mgr.validateSandboxPath("../etc/passwd"));
    try testing.expectError(LabManagerError.SandboxEscapeDetected, mgr.validateSandboxPath("..\\Windows\\System32"));
    try testing.expectError(LabManagerError.SandboxEscapeDetected, mgr.validateSandboxPath("/usr/local/bin"));
    try testing.expectError(LabManagerError.SandboxEscapeDetected, mgr.validateSandboxPath("C:\\autoexec.bat"));
    try mgr.validateSandboxPath("active_state.json");
    try mgr.validateSandboxPath("temp_cert.pem");
}

test "lab manager: repeatable setup, status, and cleanup lifecycle" {
    const test_dir = "test_lab_lifecycle_sandbox";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    var mgr = LabManager.init(testing.allocator, test_dir);
    defer mgr.cleanup() catch {};

    // Cycle 1: setup dns_failure
    {
        var s1 = try mgr.setupScenario("dns_failure");
        defer s1.deinit(testing.allocator);

        try testing.expectEqualStrings("dns_failure", s1.scenario_id);
        try testing.expect(s1.is_synthetic);

        var st = (try mgr.getStatus()).?;
        defer st.deinit(testing.allocator);
        try testing.expectEqualStrings("dns_failure", st.scenario_id);

        try mgr.cleanup();
        try testing.expect((try mgr.getStatus()) == null);
    }

    // Cycle 2: setup http_security_header_violation (spawns loopback service)
    {
        var s2 = try mgr.setupScenario("http_security_header_violation");
        defer s2.deinit(testing.allocator);

        try testing.expectEqualStrings("http_security_header_violation", s2.scenario_id);
        try testing.expect(s2.port > 0);
        try testing.expectEqualStrings("127.0.0.1", s2.bind_ip);

        var st2 = (try mgr.getStatus()).?;
        defer st2.deinit(testing.allocator);
        try testing.expectEqualStrings("http_security_header_violation", st2.scenario_id);
        try testing.expectEqual(s2.port, st2.port);

        try mgr.cleanup();
        try testing.expect((try mgr.getStatus()) == null);
    }
}
