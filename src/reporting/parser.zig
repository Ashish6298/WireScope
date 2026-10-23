const std = @import("std");
const testing = std.testing;
const schema = @import("schema.zig");
const json_mod = @import("json.zig");

const AssessmentReportData = json_mod.AssessmentReportData;
const FindingItem = json_mod.FindingItem;
const CheckItem = json_mod.CheckItem;
const DnsObsItem = json_mod.DnsObsItem;
const TcpObsItem = json_mod.TcpObsItem;
const TlsObsItem = json_mod.TlsObsItem;
const HttpObsItem = json_mod.HttpObsItem;
const ListenerObsItem = json_mod.ListenerObsItem;
const AssetItem = json_mod.AssetItem;
const PolicyResultItem = json_mod.PolicyResultItem;
const LimitationItem = json_mod.LimitationItem;
const TaskFailureItem = json_mod.TaskFailureItem;

pub const ParsedReport = struct {
    arena: std.heap.ArenaAllocator,
    data: AssessmentReportData,

    pub fn deinit(self: *ParsedReport) void {
        self.arena.deinit();
    }
};

fn getString(val: ?std.json.Value) ?[]const u8 {
    if (val) |v| {
        if (v == .string) return v.string;
    }
    return null;
}

fn getInt(comptime T: type, val: ?std.json.Value) ?T {
    if (val) |v| {
        if (v == .integer) return @intCast(v.integer);
    }
    return null;
}

fn getBool(val: ?std.json.Value, default_val: bool) bool {
    if (val) |v| {
        if (v == .bool) return v.bool;
    }
    return default_val;
}

/// Parses a validated report JSON string into an AssessmentReportData instance
pub fn parseReportFromJson(allocator: std.mem.Allocator, json_str: []const u8) !ParsedReport {
    // 1. Schema Validation first
    try schema.validateReportJson(allocator, json_str);

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const parsed_json = try std.json.parseFromSlice(std.json.Value, arena_allocator, json_str, .{});
    const root = parsed_json.value.object;

    // 2. Metadata Block
    const meta = root.get("metadata").?.object;
    const assessment_id = meta.get("assessment_id").?.string;
    const profile_id = meta.get("profile_id").?.string;
    const profile_name = meta.get("profile_name").?.string;
    const started_at_ms = meta.get("started_at_ms").?.integer;
    const completed_at_ms = meta.get("completed_at_ms").?.integer;
    const duration_ms: u64 = @intCast(meta.get("duration_ms").?.integer);
    const status = meta.get("status").?.string;
    const manifest_hash_str = meta.get("manifest_hash").?.string;
    var manifest_hash: [64]u8 = [_]u8{'0'} ** 64;
    const copy_len = @min(64, manifest_hash_str.len);
    @memcpy(manifest_hash[0..copy_len], manifest_hash_str[0..copy_len]);

    // 3. Scope Block
    const scope = root.get("scope").?.object;
    const targets_arr = scope.get("targets").?.array;
    var targets = try arena_allocator.alloc([]const u8, targets_arr.items.len);
    for (targets_arr.items, 0..) |t, i| {
        targets[i] = t.string;
    }

    const ports_arr = scope.get("ports").?.array;
    var ports = try arena_allocator.alloc(u16, ports_arr.items.len);
    for (ports_arr.items, 0..) |p, i| {
        ports[i] = @intCast(p.integer);
    }

    var exclusions: [][]const u8 = &.{};
    if (scope.get("exclusions")) |ex_val| {
        if (ex_val == .array) {
            exclusions = try arena_allocator.alloc([]const u8, ex_val.array.items.len);
            for (ex_val.array.items, 0..) |ex, i| {
                exclusions[i] = ex.string;
            }
        }
    }

    const rate_limit_rps: u32 = @intCast(scope.get("rate_limit_rps").?.integer);
    const timeout_ms: u64 = @intCast(scope.get("timeout_ms").?.integer);
    const allow_out_of_scope_redirects = getBool(scope.get("allow_out_of_scope_redirects"), false);

    // 4. Execution / Completion State Block
    const exec_val = if (root.get("completion_state")) |cs| cs else if (root.get("execution")) |ex| ex else return error.MissingRequiredField;
    const exec = exec_val.object;
    const tasks_planned: usize = @intCast(exec.get("tasks_planned").?.integer);
    const tasks_executed: usize = @intCast(exec.get("tasks_executed").?.integer);
    const tasks_succeeded: usize = @intCast(exec.get("tasks_succeeded").?.integer);
    const tasks_failed: usize = @intCast(exec.get("tasks_failed").?.integer);
    const is_complete = exec.get("is_complete").?.bool;
    const interruption_reason = getString(exec.get("interruption_reason"));

    // 5. Checks Block
    const checks_arr = root.get("checks").?.array;
    var checks = try arena_allocator.alloc(CheckItem, checks_arr.items.len);
    for (checks_arr.items, 0..) |c_val, i| {
        const c_obj = c_val.object;
        checks[i] = CheckItem{
            .sequence_id = @intCast(c_obj.get("sequence_id").?.integer),
            .check_type = c_obj.get("check_type").?.string,
            .target = c_obj.get("target").?.string,
            .status = c_obj.get("status").?.string,
            .duration_ms = @intCast(c_obj.get("duration_ms").?.integer),
        };
    }

    // 6. Observations Block
    const obs = root.get("observations").?.object;

    // DNS
    const dns_arr = obs.get("dns").?.array;
    var dns_obs = try arena_allocator.alloc(DnsObsItem, dns_arr.items.len);
    for (dns_arr.items, 0..) |d_val, i| {
        const d_obj = d_val.object;
        const answers_arr = d_obj.get("answers").?.array;
        var answers = try arena_allocator.alloc([]const u8, answers_arr.items.len);
        for (answers_arr.items, 0..) |ans_val, j| {
            answers[j] = ans_val.string;
        }
        dns_obs[i] = DnsObsItem{
            .target = d_obj.get("target").?.string,
            .answers = answers,
            .is_success = d_obj.get("is_success").?.bool,
            .duration_ms = @intCast(d_obj.get("duration_ms").?.integer),
        };
    }

    // TCP
    const tcp_arr = obs.get("tcp").?.array;
    var tcp_obs = try arena_allocator.alloc(TcpObsItem, tcp_arr.items.len);
    for (tcp_arr.items, 0..) |t_val, i| {
        const t_obj = t_val.object;
        tcp_obs[i] = TcpObsItem{
            .target = t_obj.get("target").?.string,
            .port = @intCast(t_obj.get("port").?.integer),
            .is_open = t_obj.get("is_open").?.bool,
            .rtt_ms = getInt(u32, t_obj.get("rtt_ms")),
        };
    }

    // TLS
    const tls_arr = obs.get("tls").?.array;
    var tls_obs = try arena_allocator.alloc(TlsObsItem, tls_arr.items.len);
    for (tls_arr.items, 0..) |tl_val, i| {
        const tl_obj = tl_val.object;
        tls_obs[i] = TlsObsItem{
            .target = tl_obj.get("target").?.string,
            .port = @intCast(tl_obj.get("port").?.integer),
            .protocol_version = tl_obj.get("protocol_version").?.string,
            .hostname_matches = tl_obj.get("hostname_matches").?.bool,
            .is_valid_chain = tl_obj.get("is_valid_chain").?.bool,
            .days_to_expiration = getInt(i32, tl_obj.get("days_to_expiration")),
        };
    }

    // HTTP
    const http_arr = obs.get("http").?.array;
    var http_obs = try arena_allocator.alloc(HttpObsItem, http_arr.items.len);
    for (http_arr.items, 0..) |h_val, i| {
        const h_obj = h_val.object;
        http_obs[i] = HttpObsItem{
            .target_url = h_obj.get("target_url").?.string,
            .status_code = @intCast(h_obj.get("status_code").?.integer),
            .is_https = h_obj.get("is_https").?.bool,
            .is_html = h_obj.get("is_html").?.bool,
            .is_json_api = h_obj.get("is_json_api").?.bool,
            .hsts_header = getString(h_obj.get("hsts_header")),
            .csp_header = getString(h_obj.get("csp_header")),
            .x_content_type_options = getString(h_obj.get("x_content_type_options")),
        };
    }

    // Listeners
    const lis_arr = obs.get("listeners").?.array;
    var listener_obs = try arena_allocator.alloc(ListenerObsItem, lis_arr.items.len);
    for (lis_arr.items, 0..) |l_val, i| {
        const l_obj = l_val.object;
        listener_obs[i] = ListenerObsItem{
            .transport = l_obj.get("transport").?.string,
            .address = l_obj.get("address").?.string,
            .port = @intCast(l_obj.get("port").?.integer),
            .binding_type = l_obj.get("binding_type").?.string,
            .pid = getInt(u32, l_obj.get("pid")),
            .process_name = getString(l_obj.get("process_name")),
            .is_unlisted = getBool(l_obj.get("is_unlisted"), false),
            .permission_limited = getBool(l_obj.get("permission_limited"), false),
        };
    }

    // 7. Assets Block
    const assets_arr = root.get("assets").?.array;
    var assets = try arena_allocator.alloc(AssetItem, assets_arr.items.len);
    for (assets_arr.items, 0..) |a_val, i| {
        const a_obj = a_val.object;
        const open_p_arr = a_obj.get("open_ports").?.array;
        var op_ports = try arena_allocator.alloc(u16, open_p_arr.items.len);
        for (open_p_arr.items, 0..) |op, j| {
            op_ports[j] = @intCast(op.integer);
        }
        assets[i] = AssetItem{
            .target = a_obj.get("target").?.string,
            .ip_address = getString(a_obj.get("ip_address")),
            .open_ports = op_ports,
            .service_banner = getString(a_obj.get("service_banner")),
        };
    }

    // 8. Findings Block
    const findings_arr = root.get("findings").?.array;
    var findings = try arena_allocator.alloc(FindingItem, findings_arr.items.len);
    for (findings_arr.items, 0..) |f_val, i| {
        const f_obj = f_val.object;
        findings[i] = FindingItem{
            .rule_id = f_obj.get("rule_id").?.string,
            .rule_version = @intCast(f_obj.get("rule_version").?.integer),
            .title = f_obj.get("title").?.string,
            .severity = f_obj.get("severity").?.string,
            .confidence = f_obj.get("confidence").?.string,
            .evidence = f_obj.get("evidence").?.string,
            .remediation = f_obj.get("remediation").?.string,
            .target = f_obj.get("target").?.string,
        };
    }

    // 9. Policy Results Block
    const pol_arr = root.get("policy_results").?.array;
    var policy_results = try arena_allocator.alloc(PolicyResultItem, pol_arr.items.len);
    for (pol_arr.items, 0..) |p_val, i| {
        const p_obj = p_val.object;
        policy_results[i] = PolicyResultItem{
            .rule_id = p_obj.get("rule_id").?.string,
            .outcome = p_obj.get("outcome").?.string,
            .target = p_obj.get("target").?.string,
            .message = p_obj.get("message").?.string,
        };
    }

    // 10. Limitations Block
    const lim_arr = root.get("limitations").?.array;
    var limitations = try arena_allocator.alloc(LimitationItem, lim_arr.items.len);
    for (lim_arr.items, 0..) |lim_val, i| {
        const lim_obj = lim_val.object;
        limitations[i] = LimitationItem{
            .category = lim_obj.get("category").?.string,
            .component = lim_obj.get("component").?.string,
            .description = lim_obj.get("description").?.string,
        };
    }

    // 11. Task Failures Block
    const tf_arr = root.get("task_failures").?.array;
    var task_failures = try arena_allocator.alloc(TaskFailureItem, tf_arr.items.len);
    for (tf_arr.items, 0..) |tf_val, i| {
        const tf_obj = tf_val.object;
        task_failures[i] = TaskFailureItem{
            .sequence_id = @intCast(tf_obj.get("sequence_id").?.integer),
            .check_type = tf_obj.get("check_type").?.string,
            .target = tf_obj.get("target").?.string,
            .error_message = tf_obj.get("error_message").?.string,
            .duration_ms = @intCast(tf_obj.get("duration_ms").?.integer),
        };
    }

    return ParsedReport{
        .arena = arena,
        .data = AssessmentReportData{
            .assessment_id = assessment_id,
            .profile_id = profile_id,
            .profile_name = profile_name,
            .started_at_ms = started_at_ms,
            .completed_at_ms = completed_at_ms,
            .duration_ms = duration_ms,
            .status = status,
            .manifest_hash = manifest_hash,
            .targets = targets,
            .ports = ports,
            .exclusions = exclusions,
            .rate_limit_rps = rate_limit_rps,
            .timeout_ms = timeout_ms,
            .allow_out_of_scope_redirects = allow_out_of_scope_redirects,
            .tasks_planned = tasks_planned,
            .tasks_executed = tasks_executed,
            .tasks_succeeded = tasks_succeeded,
            .tasks_failed = tasks_failed,
            .is_complete = is_complete,
            .interruption_reason = interruption_reason,
            .checks = checks,
            .dns_obs = dns_obs,
            .tcp_obs = tcp_obs,
            .tls_obs = tls_obs,
            .http_obs = http_obs,
            .listener_obs = listener_obs,
            .assets = assets,
            .findings = findings,
            .policy_results = policy_results,
            .limitations = limitations,
            .task_failures = task_failures,
        },
    };
}

test "parser: parseReportFromJson roundtrips accurately" {
    const allocator = testing.allocator;

    var targets = [_][]const u8{"127.0.0.1"};
    var ports = [_]u16{443};
    var findings = [_]FindingItem{
        .{
            .rule_id = "WS-AUDIT-HTTP-HSTS-MISSING",
            .rule_version = 1,
            .title = "Missing HSTS",
            .severity = "medium",
            .confidence = "confirmed",
            .evidence = "Header missing",
            .remediation = "Enable HSTS",
            .target = "https://127.0.0.1:443/",
        },
    };

    var src_data = AssessmentReportData{
        .assessment_id = "asm-roundtrip-1",
        .profile_id = "local-audit",
        .profile_name = "Local Audit",
        .started_at_ms = 1000,
        .completed_at_ms = 2000,
        .duration_ms = 1000,
        .status = "completed",
        .manifest_hash = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".*,
        .targets = &targets,
        .ports = &ports,
        .rate_limit_rps = 10,
        .timeout_ms = 5000,
        .tasks_planned = 1,
        .tasks_executed = 1,
        .tasks_succeeded = 1,
        .tasks_failed = 0,
        .is_complete = true,
        .findings = &findings,
    };

    const json_str = try json_mod.serializeReport(allocator, &src_data);
    defer allocator.free(json_str);

    var parsed = try parseReportFromJson(allocator, json_str);
    defer parsed.deinit();

    try testing.expectEqualStrings("asm-roundtrip-1", parsed.data.assessment_id);
    try testing.expectEqualStrings("local-audit", parsed.data.profile_id);
    try testing.expectEqualStrings("completed", parsed.data.status);
    try testing.expectEqual(true, parsed.data.is_complete);
    try testing.expectEqual(@as(usize, 1), parsed.data.findings.len);
    try testing.expectEqualStrings("WS-AUDIT-HTTP-HSTS-MISSING", parsed.data.findings[0].rule_id);
}
