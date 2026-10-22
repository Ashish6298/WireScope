const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");
const runner_mod = @import("runner.zig");
const audit = @import("../audit/root.zig");

pub const Severity = core.models.Severity;
pub const Confidence = core.models.Confidence;
pub const FindingStatus = core.models.FindingStatus;

pub const FixVerificationOutcome = enum {
    verified_fixed,
    still_failing,
    inconclusive,

    pub fn toSlice(self: FixVerificationOutcome) []const u8 {
        return @tagName(self);
    }
};

pub const EvidenceEntry = struct {
    assessment_id: []const u8,
    observed_at_ms: i64,
    evidence_text: []const u8,

    pub fn deinit(self: *EvidenceEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.assessment_id);
        allocator.free(self.evidence_text);
    }

    pub fn clone(self: *const EvidenceEntry, allocator: std.mem.Allocator) !EvidenceEntry {
        return .{
            .assessment_id = try allocator.dupe(u8, self.assessment_id),
            .observed_at_ms = self.observed_at_ms,
            .evidence_text = try allocator.dupe(u8, self.evidence_text),
        };
    }
};

pub const StatusTransition = struct {
    from_status: FindingStatus,
    to_status: FindingStatus,
    transitioned_at_ms: i64,
    reason: []const u8,
    supporting_evidence: ?[]const u8 = null,

    pub fn deinit(self: *StatusTransition, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
        if (self.supporting_evidence) |s| allocator.free(s);
    }

    pub fn clone(self: *const StatusTransition, allocator: std.mem.Allocator) !StatusTransition {
        return .{
            .from_status = self.from_status,
            .to_status = self.to_status,
            .transitioned_at_ms = self.transitioned_at_ms,
            .reason = try allocator.dupe(u8, self.reason),
            .supporting_evidence = if (self.supporting_evidence) |s| try allocator.dupe(u8, s) else null,
        };
    }
};

pub fn generateFindingId(allocator: std.mem.Allocator, rule_id: []const u8, affected_target: []const u8) ![]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("wirescope-finding-v1:");
    hasher.update(rule_id);
    hasher.update(":");
    hasher.update(affected_target);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);

    return std.fmt.allocPrint(allocator, "WS-FND-{s}", .{hex[0..16]});
}

pub const TrackedFinding = struct {
    id: []const u8,
    rule_id: []const u8,
    rule_version: u32,
    title: []const u8,
    affected_target: []const u8,
    severity: Severity,
    confidence: Confidence,
    severity_rationale: []const u8,
    remediation: []const u8,
    limitations: []const u8,
    status: FindingStatus,
    first_seen_ms: i64,
    last_seen_ms: i64,
    occurrence_count: u32,
    evidence_history: std.ArrayListUnmanaged(EvidenceEntry),
    status_history: std.ArrayListUnmanaged(StatusTransition),

    pub fn deinit(self: *TrackedFinding, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.rule_id);
        allocator.free(self.title);
        allocator.free(self.affected_target);
        allocator.free(self.severity_rationale);
        allocator.free(self.remediation);
        allocator.free(self.limitations);

        for (self.evidence_history.items) |*ev| ev.deinit(allocator);
        self.evidence_history.deinit(allocator);

        for (self.status_history.items) |*st| st.deinit(allocator);
        self.status_history.deinit(allocator);
    }

    pub fn clone(self: *const TrackedFinding, allocator: std.mem.Allocator) !TrackedFinding {
        var ev_list = try std.ArrayListUnmanaged(EvidenceEntry).initCapacity(allocator, self.evidence_history.items.len);
        errdefer ev_list.deinit(allocator);
        for (self.evidence_history.items) |ev| {
            try ev_list.append(allocator, try ev.clone(allocator));
        }

        var st_list = try std.ArrayListUnmanaged(StatusTransition).initCapacity(allocator, self.status_history.items.len);
        errdefer st_list.deinit(allocator);
        for (self.status_history.items) |st| {
            try st_list.append(allocator, try st.clone(allocator));
        }

        return .{
            .id = try allocator.dupe(u8, self.id),
            .rule_id = try allocator.dupe(u8, self.rule_id),
            .rule_version = self.rule_version,
            .title = try allocator.dupe(u8, self.title),
            .affected_target = try allocator.dupe(u8, self.affected_target),
            .severity = self.severity,
            .confidence = self.confidence,
            .severity_rationale = try allocator.dupe(u8, self.severity_rationale),
            .remediation = try allocator.dupe(u8, self.remediation),
            .limitations = try allocator.dupe(u8, self.limitations),
            .status = self.status,
            .first_seen_ms = self.first_seen_ms,
            .last_seen_ms = self.last_seen_ms,
            .occurrence_count = self.occurrence_count,
            .evidence_history = ev_list,
            .status_history = st_list,
        };
    }
};

pub const FindingsTracker = struct {
    allocator: std.mem.Allocator,
    findings: std.StringHashMapUnmanaged(TrackedFinding),

    pub fn init(allocator: std.mem.Allocator) FindingsTracker {
        return .{
            .allocator = allocator,
            .findings = std.StringHashMapUnmanaged(TrackedFinding){},
        };
    }

    pub fn deinit(self: *FindingsTracker) void {
        var iter = self.findings.valueIterator();
        while (iter.next()) |f| {
            f.deinit(self.allocator);
        }
        self.findings.deinit(self.allocator);
    }

    /// Ingest a single raw finding into the tracked store, handling deduplication and evidence preservation
    pub fn ingestFinding(
        self: *FindingsTracker,
        rule_id: []const u8,
        rule_version: u32,
        title: []const u8,
        affected_target: []const u8,
        severity: Severity,
        confidence: Confidence,
        severity_rationale: []const u8,
        evidence: []const u8,
        remediation: []const u8,
        limitations: []const u8,
        assessment_id: []const u8,
        observed_at_ms: i64,
    ) !*TrackedFinding {
        const fid = try generateFindingId(self.allocator, rule_id, affected_target);
        defer self.allocator.free(fid);

        if (self.findings.getPtr(fid)) |existing| {
            // Deduplication logic:
            // 1. Increment occurrence counter
            existing.occurrence_count += 1;
            existing.last_seen_ms = observed_at_ms;

            // 2. Retain historical evidence entry
            try existing.evidence_history.append(self.allocator, .{
                .assessment_id = try self.allocator.dupe(u8, assessment_id),
                .observed_at_ms = observed_at_ms,
                .evidence_text = try self.allocator.dupe(u8, evidence),
            });

            // 3. Handle lifecycle transition:
            // If it was 'new', subsequent observation makes it 'confirmed'.
            // If it was 'fixed' or 'accepted', seeing it again marks it 'reopened'!
            if (existing.status == .new) {
                try existing.status_history.append(self.allocator, .{
                    .from_status = .new,
                    .to_status = .confirmed,
                    .transitioned_at_ms = observed_at_ms,
                    .reason = try self.allocator.dupe(u8, "Re-observed in subsequent assessment; confirmed reproducible gap."),
                    .supporting_evidence = try self.allocator.dupe(u8, evidence),
                });
                existing.status = .confirmed;
            } else if (existing.status == .fixed or existing.status == .accepted) {
                try existing.status_history.append(self.allocator, .{
                    .from_status = existing.status,
                    .to_status = .reopened,
                    .transitioned_at_ms = observed_at_ms,
                    .reason = try self.allocator.dupe(u8, "Re-observed after remediation or acceptance; gap reopened."),
                    .supporting_evidence = try self.allocator.dupe(u8, evidence),
                });
                existing.status = .reopened;
            }

            return existing;
        }

        // Brand new finding
        var ev_list = std.ArrayListUnmanaged(EvidenceEntry){};
        errdefer ev_list.deinit(self.allocator);
        try ev_list.append(self.allocator, .{
            .assessment_id = try self.allocator.dupe(u8, assessment_id),
            .observed_at_ms = observed_at_ms,
            .evidence_text = try self.allocator.dupe(u8, evidence),
        });

        var st_list = std.ArrayListUnmanaged(StatusTransition){};
        errdefer st_list.deinit(self.allocator);
        try st_list.append(self.allocator, .{
            .from_status = .new,
            .to_status = .new,
            .transitioned_at_ms = observed_at_ms,
            .reason = try self.allocator.dupe(u8, "Initial observation in assessment run."),
            .supporting_evidence = try self.allocator.dupe(u8, evidence),
        });

        const new_finding = TrackedFinding{
            .id = try self.allocator.dupe(u8, fid),
            .rule_id = try self.allocator.dupe(u8, rule_id),
            .rule_version = rule_version,
            .title = try self.allocator.dupe(u8, title),
            .affected_target = try self.allocator.dupe(u8, affected_target),
            .severity = severity,
            .confidence = confidence,
            .severity_rationale = try self.allocator.dupe(u8, severity_rationale),
            .remediation = try self.allocator.dupe(u8, remediation),
            .limitations = try self.allocator.dupe(u8, limitations),
            .status = .new,
            .first_seen_ms = observed_at_ms,
            .last_seen_ms = observed_at_ms,
            .occurrence_count = 1,
            .evidence_history = ev_list,
            .status_history = st_list,
        };

        try self.findings.put(self.allocator, new_finding.id, new_finding);
        return self.findings.getPtr(fid).?;
    }

    /// Ingest all findings from a completed or partial assessment
    pub fn ingestAssessment(self: *FindingsTracker, assessment: *const runner_mod.AssessmentResult) !usize {
        var ingested_count: usize = 0;
        for (assessment.findings.items) |f| {
            _ = try self.ingestFinding(
                f.rule_id,
                f.rule_version,
                f.title,
                assessment.profile_id,
                f.severity,
                f.confidence,
                f.severity_rationale,
                f.evidence,
                f.remediation,
                f.limitations,
                assessment.manifest.assessment_id,
                assessment.manifest.completed_at_ms,
            );
            ingested_count += 1;
        }
        return ingested_count;
    }

    /// Transition a finding's status explicitly (e.g. accepted risk, not applicable)
    pub fn updateStatus(
        self: *FindingsTracker,
        finding_id: []const u8,
        new_status: FindingStatus,
        reason: []const u8,
        supporting_evidence: ?[]const u8,
    ) !void {
        const finding = self.findings.getPtr(finding_id) orelse return error.FindingNotFound;
        const old_status = finding.status;
        if (old_status == new_status) return;

        try finding.status_history.append(self.allocator, .{
            .from_status = old_status,
            .to_status = new_status,
            .transitioned_at_ms = std.time.milliTimestamp(),
            .reason = try self.allocator.dupe(u8, reason),
            .supporting_evidence = if (supporting_evidence) |s| try self.allocator.dupe(u8, s) else null,
        });
        finding.status = new_status;
    }

    /// Fix verification: Strictly enforces that a finding can only be marked fixed
    /// if affirmative supporting evidence is supplied! A missing observation or timeout
    /// is returned as inconclusive and NEVER transitions to fixed.
    pub fn verifyFix(
        self: *FindingsTracker,
        finding_id: []const u8,
        passed_rule_eval: bool,
        verification_evidence: ?[]const u8,
    ) !FixVerificationOutcome {
        const finding = self.findings.getPtr(finding_id) orelse return error.FindingNotFound;

        if (passed_rule_eval and verification_evidence != null and verification_evidence.?.len > 0) {
            // Affirmative proof of resolution!
            try self.updateStatus(
                finding_id,
                .fixed,
                "Remediation verified: active check confirmed target satisfies defensive rule standard.",
                verification_evidence,
            );
            return .verified_fixed;
        } else if (!passed_rule_eval and verification_evidence != null) {
            // Still failing
            return .still_failing;
        } else {
            // Missing observation, timeout, or lack of proof: INCONCLUSIVE INVARIANT
            // Do NOT mark as fixed!
            try finding.status_history.append(self.allocator, .{
                .from_status = finding.status,
                .to_status = finding.status, // remains unchanged
                .transitioned_at_ms = std.time.milliTimestamp(),
                .reason = try self.allocator.dupe(u8, "Fix verification inconclusive: observation was missing, timed out, or incomplete; cannot assert issue is fixed without affirmative proof."),
                .supporting_evidence = null,
            });
            return .inconclusive;
        }
    }

    pub fn getFinding(self: *const FindingsTracker, id: []const u8) ?*const TrackedFinding {
        return self.findings.getPtr(id);
    }

    pub fn toTerminal(self: *const FindingsTracker, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE DEFENSIVE FINDINGS & REMEDIATION TRACKER
            \\================================================================================
            \\Tracked Findings:   {d}
            \\
            \\  ID                Status       Occur  Severity  Rule ID                 Target
            \\  --------------------------------------------------------------------------------
            \\
        , .{self.findings.count()});

        var iter = self.findings.iterator();
        while (iter.next()) |entry| {
            const f = entry.value_ptr.*;
            try writer.print("  {s:<17} {s:<12} {d:<6} {s:<9} {s:<23} {s}\n", .{
                f.id,
                f.status.toSlice(),
                f.occurrence_count,
                f.severity.toSlice(),
                f.rule_id,
                f.affected_target,
            });
        }

        try writer.print(
            \\================================================================================
            \\WireScope Remediation Invariant:
            \\  Evidence is preserved through deduplication.
            \\  Fix verification requires affirmative supporting proof; missing observations never imply a fix.
            \\================================================================================
            \\
        , .{});
    }

    pub fn toJson(self: *const FindingsTracker, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"findings_tracker","schema_version":1,"total_findings":{d},"findings":[
        , .{self.findings.count()});

        var iter = self.findings.iterator();
        var idx: usize = 0;
        while (iter.next()) |entry| {
            if (idx > 0) try writer.print(",", .{});
            const f = entry.value_ptr.*;
            try writer.print(
                \\{{"id":"{s}","rule_id":"{s}","status":"{s}","occurrences":{d},"severity":"{s}","confidence":"{s}","first_seen":{d},"last_seen":{d},"evidence_count":{d},"transitions_count":{d}}}
            , .{
                f.id,
                f.rule_id,
                f.status.toSlice(),
                f.occurrence_count,
                f.severity.toSlice(),
                f.confidence.toSlice(),
                f.first_seen_ms,
                f.last_seen_ms,
                f.evidence_history.items.len,
                f.status_history.items.len,
            });
            idx += 1;
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const FindingsTracker, writer: anytype) !void {
        try writer.print(
            \\# WireScope Defensive Findings & Remediation Tracker
            \\
            \\**Total Tracked Findings:** {d}  
            \\
            \\> [!NOTE]
            \\> Findings maintain an immutable historical evidence trail. Missing observations never imply that an issue is resolved.
            \\
            \\| Finding ID | Status | Occurrences | Severity | Rule ID | Target |
            \\| :--- | :--- | :---: | :--- | :--- | :--- |
            \\
        , .{self.findings.count()});

        var iter = self.findings.iterator();
        while (iter.next()) |entry| {
            const f = entry.value_ptr.*;
            try writer.print("| `{s}` | `{s}` | {d} | `{s}` | `{s}` | {s} |\n", .{
                f.id,
                f.status.toSlice(),
                f.occurrence_count,
                f.severity.toSlice(),
                f.rule_id,
                f.affected_target,
            });
        }
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 10.3 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "findings tracker: stable identities across comparable assessments" {
    const allocator = testing.allocator;

    const id1 = try generateFindingId(allocator, "WS-RULE-TLS-MIN-VERSION", "https://api.example.com");
    defer allocator.free(id1);

    const id2 = try generateFindingId(allocator, "WS-RULE-TLS-MIN-VERSION", "https://api.example.com");
    defer allocator.free(id2);

    // Acceptance criterion 1: stable identities across comparable assessments
    try testing.expectEqualStrings(id1, id2);
    try testing.expect(std.mem.startsWith(u8, id1, "WS-FND-"));
}

test "findings tracker: deduplication preserves evidence history and increments occurrences" {
    const allocator = testing.allocator;
    var tracker = FindingsTracker.init(allocator);
    defer tracker.deinit();

    // 1. Initial observation in Assessment 1
    const f1 = try tracker.ingestFinding(
        "WS-RULE-HTTP-HSTS-POLICY",
        1,
        "Require HTTP Strict Transport Security (HSTS) on HTTPS",
        "https://example.com",
        .medium,
        .confirmed,
        "Permits unencrypted downgrade attacks.",
        "Strict-Transport-Security header absent",
        "Add HSTS header.",
        "Observation boundary: single request.",
        "asm-100",
        1700000000000,
    );

    try testing.expectEqual(FindingStatus.new, f1.status);
    try testing.expectEqual(@as(u32, 1), f1.occurrence_count);
    try testing.expectEqual(@as(usize, 1), f1.evidence_history.items.len);

    // 2. Re-observation in Assessment 2 (same target and rule)
    const f2 = try tracker.ingestFinding(
        "WS-RULE-HTTP-HSTS-POLICY",
        1,
        "Require HTTP Strict Transport Security (HSTS) on HTTPS",
        "https://example.com",
        .medium,
        .confirmed,
        "Permits unencrypted downgrade attacks.",
        "Strict-Transport-Security header absent in second run",
        "Add HSTS header.",
        "Observation boundary: single request.",
        "asm-200",
        1700000050000,
    );

    // Acceptance criterion 2: evidence is retained through deduplication!
    try testing.expectEqualStrings(f1.id, f2.id);
    try testing.expectEqual(FindingStatus.confirmed, f2.status);
    try testing.expectEqual(@as(u32, 2), f2.occurrence_count);
    try testing.expectEqual(@as(usize, 2), f2.evidence_history.items.len);
    try testing.expectEqualStrings("asm-100", f2.evidence_history.items[0].assessment_id);
    try testing.expectEqualStrings("asm-200", f2.evidence_history.items[1].assessment_id);
}

test "findings tracker: full lifecycle status transitions and history audit trail" {
    const allocator = testing.allocator;
    var tracker = FindingsTracker.init(allocator);
    defer tracker.deinit();

    const f = try tracker.ingestFinding(
        "WS-RULE-EXPOSURE-WILDCARD-BINDING",
        1,
        "Audit Unapproved Wildcard Socket Bindings",
        "0.0.0.0:8080",
        .medium,
        .confirmed,
        "Exposes port across all interfaces.",
        "Socket bound to 0.0.0.0:8080",
        "Bind to 127.0.0.1.",
        "Read-only inspection.",
        "asm-1",
        1000,
    );

    const fid = try allocator.dupe(u8, f.id);
    defer allocator.free(fid);

    // Acceptance criterion 3: status transitions and history are tested
    try testing.expectEqual(FindingStatus.new, tracker.getFinding(fid).?.status);

    // Operator marks risk as accepted
    try tracker.updateStatus(fid, .accepted, "Operator approved development listener", null);
    try testing.expectEqual(FindingStatus.accepted, tracker.getFinding(fid).?.status);

    // Seeing it again marks it reopened
    _ = try tracker.ingestFinding(
        "WS-RULE-EXPOSURE-WILDCARD-BINDING",
        1,
        "Audit Unapproved Wildcard Socket Bindings",
        "0.0.0.0:8080",
        .medium,
        .confirmed,
        "Exposes port across all interfaces.",
        "Socket still bound to 0.0.0.0:8080",
        "Bind to 127.0.0.1.",
        "Read-only inspection.",
        "asm-2",
        2000,
    );
    try testing.expectEqual(FindingStatus.reopened, tracker.getFinding(fid).?.status);

    // Verify audit trail contains all recorded transitions
    const final_f = tracker.getFinding(fid).?;
    try testing.expect(final_f.status_history.items.len >= 3);
}

test "findings tracker: fix verification requires supporting proof or remains inconclusive" {
    const allocator = testing.allocator;
    var tracker = FindingsTracker.init(allocator);
    defer tracker.deinit();

    const f = try tracker.ingestFinding(
        "WS-RULE-TLS-MIN-VERSION",
        1,
        "Enforce Modern TLS Protocol Version (TLS 1.2+)",
        "https://insecure.local",
        .high,
        .confirmed,
        "TLS 1.0 is deprecated.",
        "Negotiated TLSv1.0",
        "Configure TLS 1.2+.",
        "Handshake observation.",
        "asm-1",
        1000,
    );

    const fid = try allocator.dupe(u8, f.id);
    defer allocator.free(fid);

    // 1. Incomplete observation / timeout: MUST NOT mark as fixed!
    // Acceptance criterion 4: fix verification requires supporting evidence or is marked inconclusive
    const res_inconclusive = try tracker.verifyFix(fid, false, null);
    try testing.expectEqual(FixVerificationOutcome.inconclusive, res_inconclusive);
    try testing.expectEqual(FindingStatus.new, tracker.getFinding(fid).?.status); // Unchanged!

    // 2. Affirmative verification with positive evidence
    const res_fixed = try tracker.verifyFix(
        fid,
        true,
        "Affirmative handshake observation: server negotiated TLSv1.3 with AES-GCM.",
    );
    try testing.expectEqual(FixVerificationOutcome.verified_fixed, res_fixed);
    try testing.expectEqual(FindingStatus.fixed, tracker.getFinding(fid).?.status);
}
