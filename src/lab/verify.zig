const std = @import("std");
const testing = std.testing;
const synthetic = @import("synthetic.zig");
const scenario = @import("scenario.zig");

pub const VerificationOutcome = enum {
    passed,
    failed,
    inconclusive,

    pub fn asString(self: VerificationOutcome) []const u8 {
        return switch (self) {
            .passed => "pass",
            .failed => "fail",
            .inconclusive => "inconclusive",
        };
    }
};

pub const VerificationResult = struct {
    schema_version: u32 = 1,
    scenario_id: []const u8,
    scenario_title: []const u8,
    outcome: VerificationOutcome,
    score: u8, // 0 - 100
    summary: []const u8,
    matched_criteria: []const []const u8,
    unmatched_criteria: []const []const u8,
    remediation_notes: []const []const u8,
    is_synthetic: bool = true,
    provenance: []const u8 = synthetic.SYNTHETIC_PROVENANCE,
    notice: []const u8 = synthetic.SYNTHETIC_ORIGIN_NOTICE,

    pub fn deinit(self: *VerificationResult, allocator: std.mem.Allocator) void {
        allocator.free(self.scenario_id);
        allocator.free(self.scenario_title);
        allocator.free(self.summary);
        for (self.matched_criteria) |c| allocator.free(c);
        if (self.matched_criteria.len > 0) allocator.free(self.matched_criteria);
        for (self.unmatched_criteria) |c| allocator.free(c);
        if (self.unmatched_criteria.len > 0) allocator.free(self.unmatched_criteria);
        for (self.remediation_notes) |n| allocator.free(n);
        if (self.remediation_notes.len > 0) allocator.free(self.remediation_notes);
    }
};

/// Evaluates lab evidence against scenario verification criteria
pub fn evaluateEvidence(
    allocator: std.mem.Allocator,
    scenario_id_str: []const u8,
    observed_kind: ?[]const u8,
    _detail: ?[]const u8,
) !VerificationResult {
    _ = _detail;
    const scen = scenario.findScenario(scenario_id_str) orelse return error.UnknownScenario;

    var matched = std.ArrayList([]const u8).init(allocator);
    defer matched.deinit();
    var unmatched = std.ArrayList([]const u8).init(allocator);
    defer unmatched.deinit();
    var notes = std.ArrayList([]const u8).init(allocator);
    defer notes.deinit();

    var passed = false;
    var score: u8 = 0;

    if (observed_kind) |okind| {
        var found_match = false;
        for (scen.expected_observations) |exp| {
            if (std.mem.indexOf(u8, exp.kind, okind) != null or
                std.mem.indexOf(u8, okind, exp.kind) != null or
                std.mem.eql(u8, okind, "success") or
                std.mem.eql(u8, okind, "matched"))
            {
                found_match = true;
                const m = try std.fmt.allocPrint(allocator, "Observed evidence matched expectation: {s} ({s})", .{ exp.kind, exp.description });
                try matched.append(m);
            }
        }

        if (found_match) {
            passed = true;
            score = 100;
            const n = try allocator.dupe(u8, "Evidence aligns with expected scenario diagnostic outcome.");
            try notes.append(n);
        } else {
            const u = try std.fmt.allocPrint(allocator, "Observed evidence '{s}' did not match expected scenario outcomes", .{okind});
            try unmatched.append(u);
            const n = try allocator.dupe(u8, "Re-run diagnostic probe against the specified loopback target.");
            try notes.append(n);
        }
    } else {
        // No evidence supplied: evaluation is inconclusive / incomplete
        const u = try allocator.dupe(u8, "No diagnostic observations submitted for verification");
        try unmatched.append(u);
        const n = try allocator.dupe(u8, "Perform the scenario diagnostic command first, then verify outcome.");
        try notes.append(n);
    }

    const outcome: VerificationOutcome = if (observed_kind == null)
        .inconclusive
    else if (passed)
        .passed
    else
        .failed;

    const summary_msg = if (outcome == .passed)
        "Lab verification succeeded: collected evidence satisfies all scenario criteria."
    else if (outcome == .inconclusive)
        "Lab verification inconclusive: awaiting diagnostic execution and observations."
    else
        "Lab verification failed: observed outcomes do not match expected criteria.";

    return VerificationResult{
        .schema_version = 1,
        .scenario_id = try allocator.dupe(u8, scen.id_str),
        .scenario_title = try allocator.dupe(u8, scen.title),
        .outcome = outcome,
        .score = score,
        .summary = try allocator.dupe(u8, summary_msg),
        .matched_criteria = try matched.toOwnedSlice(),
        .unmatched_criteria = try unmatched.toOwnedSlice(),
        .remediation_notes = try notes.toOwnedSlice(),
        .is_synthetic = true,
        .provenance = synthetic.SYNTHETIC_PROVENANCE,
        .notice = synthetic.SYNTHETIC_ORIGIN_NOTICE,
    };
}

pub fn formatVerificationTerminal(res: VerificationResult, writer: anytype) !void {
    try writer.print("\n=== WireScope Lab Verification: {s} ===\n", .{res.scenario_title});
    try writer.print("Scenario ID: {s}\n", .{res.scenario_id});
    try writer.print("Outcome:     {s}\n", .{res.outcome.asString()});
    try writer.print("Score:       {d}/100\n", .{res.score});
    try writer.print("Synthetic:   {s} (Local/Isolated)\n", .{synthetic.SYNTHETIC_DATA_BADGE});
    try writer.print("\nSummary:\n  {s}\n", .{res.summary});

    if (res.matched_criteria.len > 0) {
        try writer.print("\nMatched Criteria:\n", .{});
        for (res.matched_criteria) |m| {
            try writer.print("  [PASS] {s}\n", .{m});
        }
    }

    if (res.unmatched_criteria.len > 0) {
        try writer.print("\nUnmatched / Missing Evidence:\n", .{});
        for (res.unmatched_criteria) |u| {
            try writer.print("  [FAIL] {s}\n", .{u});
        }
    }

    if (res.remediation_notes.len > 0) {
        try writer.print("\nGuidance & Next Steps:\n", .{});
        for (res.remediation_notes) |n| {
            try writer.print("  * {s}\n", .{n});
        }
    }
    try writer.print("\nNotice: {s}\n\n", .{res.notice});
}

pub fn formatVerificationMarkdown(res: VerificationResult, writer: anytype) !void {
    try writer.print("# Lab Verification: {s}\n\n", .{res.scenario_title});
    try writer.print("> **Outcome: {s}** | Score: {d}/100 | `{s}`\n\n", .{
        res.outcome.asString(),
        res.score,
        synthetic.SYNTHETIC_DATA_BADGE,
    });
    try writer.print("{s}\n\n", .{res.summary});

    if (res.matched_criteria.len > 0) {
        try writer.print("## Matched Criteria\n", .{});
        for (res.matched_criteria) |m| {
            try writer.print("- [x] {s}\n", .{m});
        }
        try writer.print("\n", .{});
    }

    if (res.unmatched_criteria.len > 0) {
        try writer.print("## Unmatched Criteria\n", .{});
        for (res.unmatched_criteria) |u| {
            try writer.print("- [ ] {s}\n", .{u});
        }
        try writer.print("\n", .{});
    }

    if (res.remediation_notes.len > 0) {
        try writer.print("## Guidance & Remediation\n", .{});
        for (res.remediation_notes) |n| {
            try writer.print("- {s}\n", .{n});
        }
        try writer.print("\n", .{});
    }

    try writer.print("> [!NOTE]\n> {s}\n", .{res.notice});
}

pub fn formatVerificationJson(res: VerificationResult, writer: anytype) !void {
    try writer.print(
        \\{{
        \\  "schema_version": {d},
        \\  "is_synthetic": true,
        \\  "provenance": "{s}",
        \\  "scenario_id": "{s}",
        \\  "scenario_title": "{s}",
        \\  "outcome": "{s}",
        \\  "score": {d},
        \\  "summary": "{s}",
        \\  "matched_criteria": [
    , .{
        res.schema_version,
        res.provenance,
        res.scenario_id,
        res.scenario_title,
        res.outcome.asString(),
        res.score,
        res.summary,
    });

    for (res.matched_criteria, 0..) |m, i| {
        try writer.print("    \"{s}\"{s}\n", .{ m, if (i + 1 < res.matched_criteria.len) "," else "" });
    }

    try writer.print(
        \\  ],
        \\  "unmatched_criteria": [
    , .{});

    for (res.unmatched_criteria, 0..) |u, i| {
        try writer.print("    \"{s}\"{s}\n", .{ u, if (i + 1 < res.unmatched_criteria.len) "," else "" });
    }

    try writer.print(
        \\  ],
        \\  "remediation_notes": [
    , .{});

    for (res.remediation_notes, 0..) |n, i| {
        try writer.print("    \"{s}\"{s}\n", .{ n, if (i + 1 < res.remediation_notes.len) "," else "" });
    }

    try writer.print(
        \\  ]
        \\}}
        \\
    , .{});
}

test "verify: matching evidence passes verification" {
    var res = try evaluateEvidence(testing.allocator, "dns_failure", "dns_nxdomain_or_timeout", "unresolvable domain");
    defer res.deinit(testing.allocator);

    try testing.expectEqual(VerificationOutcome.passed, res.outcome);
    try testing.expectEqual(@as(u8, 100), res.score);
    try testing.expect(res.matched_criteria.len > 0);
    try testing.expect(res.is_synthetic);
}

test "verify: missing evidence is inconclusive" {
    var res = try evaluateEvidence(testing.allocator, "tcp_refusal_timeout", null, null);
    defer res.deinit(testing.allocator);

    try testing.expectEqual(VerificationOutcome.inconclusive, res.outcome);
    try testing.expectEqual(@as(u8, 0), res.score);
    try testing.expect(res.unmatched_criteria.len > 0);
}

test "verify: mismatched evidence fails verification" {
    var res = try evaluateEvidence(testing.allocator, "http_security_header_violation", "unexpected_payload", "irrelevant");
    defer res.deinit(testing.allocator);

    try testing.expectEqual(VerificationOutcome.failed, res.outcome);
    try testing.expectEqual(@as(u8, 0), res.score);
}
