const std = @import("std");
const testing = std.testing;

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const REPORT_SCHEMA_ID: []const u8 = "https://wirescope.dev/schemas/assessment-report-v1.json";
pub const REPORT_DOCUMENT_TYPE: []const u8 = "wirescope_assessment_report";
pub const TOOL_NAME: []const u8 = "wirescope";
pub const TOOL_VERSION: []const u8 = "0.1.0-dev";

pub const SchemaValidationError = error{
    InvalidJson,
    NotAnObject,
    MissingRequiredField,
    InvalidFieldType,
    UnsupportedFutureSchemaVersion,
    SecretOrResponseBodyExposed,
    OutOfMemory,
};

/// Validates that a serialized report JSON strictly conforms to the versioned schema
pub fn validateReportJson(allocator: std.mem.Allocator, json_str: []const u8) SchemaValidationError!void {
    // 1. Secret and Response Body Leakage Guard
    // WireScope reports must NEVER emit HTTP response bodies, passwords, or bearer secrets by default.
    const forbidden_keys = [_][]const u8{
        "\"response_body\"",
        "\"body_content\"",
        "\"raw_body\"",
        "\"password\"",
        "\"client_secret\"",
        "\"private_key\"",
        "\"authorization_bearer\"",
    };
    for (forbidden_keys) |key| {
        if (std.mem.indexOf(u8, json_str, key) != null) {
            return SchemaValidationError.SecretOrResponseBodyExposed;
        }
    }

    // 2. Parse JSON syntax
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
        return SchemaValidationError.InvalidJson;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return SchemaValidationError.NotAnObject;
    }
    const root = parsed.value.object;

    // 3. Schema Version Verification
    const sv_val = root.get("schema_version") orelse return SchemaValidationError.MissingRequiredField;
    if (sv_val != .integer) return SchemaValidationError.InvalidFieldType;
    if (sv_val.integer > REPORT_SCHEMA_VERSION) {
        return SchemaValidationError.UnsupportedFutureSchemaVersion;
    }
    if (sv_val.integer < 1) {
        return SchemaValidationError.InvalidFieldType;
    }

    // 4. Report Type Verification
    const rt_val = root.get("report_type") orelse return SchemaValidationError.MissingRequiredField;
    if (rt_val != .string or !std.mem.eql(u8, rt_val.string, REPORT_DOCUMENT_TYPE)) {
        return SchemaValidationError.InvalidFieldType;
    }

    // 5. Tool Block
    const tool_val = root.get("tool") orelse return SchemaValidationError.MissingRequiredField;
    if (tool_val != .object) return SchemaValidationError.InvalidFieldType;
    const tool_obj = tool_val.object;
    if (tool_obj.get("name") == null or tool_obj.get("version") == null) {
        return SchemaValidationError.MissingRequiredField;
    }

    // 6. Metadata Block
    const meta_val = root.get("metadata") orelse return SchemaValidationError.MissingRequiredField;
    if (meta_val != .object) return SchemaValidationError.InvalidFieldType;
    const meta_obj = meta_val.object;
    const meta_required = [_][]const u8{
        "assessment_id",
        "profile_id",
        "profile_name",
        "started_at_ms",
        "completed_at_ms",
        "duration_ms",
        "status",
        "manifest_hash",
    };
    for (meta_required) |req| {
        if (meta_obj.get(req) == null) return SchemaValidationError.MissingRequiredField;
    }

    // Status value validation
    const status_val = meta_obj.get("status").?;
    if (status_val != .string) return SchemaValidationError.InvalidFieldType;
    const valid_statuses = [_][]const u8{ "completed", "partial", "failed", "cancelled", "not_started" };
    var is_valid_status = false;
    for (valid_statuses) |st| {
        if (std.mem.eql(u8, status_val.string, st)) {
            is_valid_status = true;
            break;
        }
    }
    if (!is_valid_status) return SchemaValidationError.InvalidFieldType;

    // 7. Scope Block
    const scope_val = root.get("scope") orelse return SchemaValidationError.MissingRequiredField;
    if (scope_val != .object) return SchemaValidationError.InvalidFieldType;
    const scope_obj = scope_val.object;
    if (scope_obj.get("targets") == null or scope_obj.get("ports") == null or scope_obj.get("rate_limit_rps") == null or scope_obj.get("timeout_ms") == null) {
        return SchemaValidationError.MissingRequiredField;
    }

    // 8. Completion State Block
    const comp_val = root.get("completion_state") orelse return SchemaValidationError.MissingRequiredField;
    if (comp_val != .object) return SchemaValidationError.InvalidFieldType;
    const comp_obj = comp_val.object;
    if (comp_obj.get("tasks_planned") == null or comp_obj.get("tasks_executed") == null or comp_obj.get("tasks_succeeded") == null or comp_obj.get("tasks_failed") == null or comp_obj.get("is_complete") == null) {
        return SchemaValidationError.MissingRequiredField;
    }

    // 9. Checks Array
    const checks_val = root.get("checks") orelse return SchemaValidationError.MissingRequiredField;
    if (checks_val != .array) return SchemaValidationError.InvalidFieldType;

    // 10. Observations Block
    const obs_val = root.get("observations") orelse return SchemaValidationError.MissingRequiredField;
    if (obs_val != .object) return SchemaValidationError.InvalidFieldType;
    const obs_obj = obs_val.object;
    if (obs_obj.get("dns") == null or obs_obj.get("tcp") == null or obs_obj.get("tls") == null or obs_obj.get("http") == null or obs_obj.get("listeners") == null) {
        return SchemaValidationError.MissingRequiredField;
    }

    // 11. Assets Array
    const assets_val = root.get("assets") orelse return SchemaValidationError.MissingRequiredField;
    if (assets_val != .array) return SchemaValidationError.InvalidFieldType;

    // 12. Findings Array
    const findings_val = root.get("findings") orelse return SchemaValidationError.MissingRequiredField;
    if (findings_val != .array) return SchemaValidationError.InvalidFieldType;

    // 13. Policy Results Array
    const pol_val = root.get("policy_results") orelse return SchemaValidationError.MissingRequiredField;
    if (pol_val != .array) return SchemaValidationError.InvalidFieldType;

    // 14. Limitations Array
    const lim_val = root.get("limitations") orelse return SchemaValidationError.MissingRequiredField;
    if (lim_val != .array) return SchemaValidationError.InvalidFieldType;
}

test "schema: validates compliant versioned report json" {
    const allocator = testing.allocator;
    const sample =
        \\{
        \\  "schema_version": 1,
        \\  "report_type": "wirescope_assessment_report",
        \\  "tool": { "name": "wirescope", "version": "0.1.0-dev" },
        \\  "metadata": {
        \\    "assessment_id": "asm-101",
        \\    "profile_id": "local-security-audit",
        \\    "profile_name": "Local Security Audit",
        \\    "started_at_ms": 1710000000000,
        \\    "completed_at_ms": 1710000005000,
        \\    "duration_ms": 5000,
        \\    "status": "completed",
        \\    "manifest_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        \\  },
        \\  "scope": {
        \\    "targets": ["127.0.0.1"],
        \\    "ports": [80, 443],
        \\    "exclusions": [],
        \\    "rate_limit_rps": 10,
        \\    "timeout_ms": 5000,
        \\    "allow_out_of_scope_redirects": false
        \\  },
        \\  "completion_state": {
        \\    "tasks_planned": 2,
        \\    "tasks_executed": 2,
        \\    "tasks_succeeded": 2,
        \\    "tasks_failed": 0,
        \\    "is_complete": true,
        \\    "interruption_reason": null
        \\  },
        \\  "checks": [],
        \\  "observations": {
        \\    "dns": [],
        \\    "tcp": [],
        \\    "tls": [],
        \\    "http": [],
        \\    "listeners": []
        \\  },
        \\  "assets": [],
        \\  "findings": [],
        \\  "policy_results": [],
        \\  "limitations": []
        \\}
    ;

    try validateReportJson(allocator, sample);
}

test "schema: rejects invalid json and missing fields" {
    const allocator = testing.allocator;

    try testing.expectError(SchemaValidationError.InvalidJson, validateReportJson(allocator, "{ not json"));
    try testing.expectError(SchemaValidationError.NotAnObject, validateReportJson(allocator, "[\"array\"]"));
    try testing.expectError(SchemaValidationError.MissingRequiredField, validateReportJson(allocator, "{\"schema_version\": 1}"));
}

test "schema: rejects future unsupported schema versions" {
    const allocator = testing.allocator;
    const future =
        \\{
        \\  "schema_version": 99,
        \\  "report_type": "wirescope_assessment_report"
        \\}
    ;
    try testing.expectError(SchemaValidationError.UnsupportedFutureSchemaVersion, validateReportJson(allocator, future));
}

test "schema: rejects response bodies or secret tokens" {
    const allocator = testing.allocator;
    const leak =
        \\{
        \\  "schema_version": 1,
        \\  "report_type": "wirescope_assessment_report",
        \\  "response_body": "<html>secret admin dashboard</html>"
        \\}
    ;
    try testing.expectError(SchemaValidationError.SecretOrResponseBodyExposed, validateReportJson(allocator, leak));
}
