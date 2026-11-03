const std = @import("std");
const testing = std.testing;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const CURRENT_TOOL_NAME: []const u8 = "wirescope";
pub const CURRENT_TOOL_VERSION: []const u8 = "1.0.0";
pub const DEFAULT_HASH_ALGO: []const u8 = "sha256";

/// Prominent security notice explaining cryptographic limits of local hashes
pub const HASH_LIMITATIONS_NOTICE: []const u8 =
    "Cryptographic Integrity Notice: WireScope report manifests use SHA-256 digests " ++
    "to detect accidental modification, filesystem bit-rot, transmission corruption, or " ++
    "localized tampering of report artifacts. However, a local hash alone does NOT prove " ++
    "author identity, establish non-repudiation, or protect against an adversary with local " ++
    "write access who can alter both the report artifact and this manifest simultaneously. " ++
    "Author verification and non-repudiation require external digital signatures " ++
    "(e.g., Ed25519, GPG, or X.509 PKI) and out-of-band trust anchors.";

pub const ManifestError = error{
    InvalidManifestSchema,
    UnsupportedFutureManifestVersion,
    ManifestCorrupt,
    ManifestHashMismatch,
    ArtifactMissing,
    ArtifactModified,
    PathTraversalEscape,
    OutOfMemory,
    IoError,
};

pub const ArtifactType = enum {
    json_report,
    markdown_report,
    terminal_summary,
    observations,
    findings,
    baseline_diff,
    other,

    pub fn toSlice(self: ArtifactType) []const u8 {
        return switch (self) {
            .json_report => "json_report",
            .markdown_report => "markdown_report",
            .terminal_summary => "terminal_summary",
            .observations => "observations",
            .findings => "findings",
            .baseline_diff => "baseline_diff",
            .other => "other",
        };
    }

    pub fn fromSlice(s: []const u8) ArtifactType {
        if (std.mem.eql(u8, s, "json_report")) return .json_report;
        if (std.mem.eql(u8, s, "markdown_report")) return .markdown_report;
        if (std.mem.eql(u8, s, "terminal_summary")) return .terminal_summary;
        if (std.mem.eql(u8, s, "observations")) return .observations;
        if (std.mem.eql(u8, s, "findings")) return .findings;
        if (std.mem.eql(u8, s, "baseline_diff")) return .baseline_diff;
        return .other;
    }
};

pub const ArtifactEntry = struct {
    path: []const u8,
    artifact_type: ArtifactType,
    hash_algo: []const u8 = DEFAULT_HASH_ALGO,
    hash: [64]u8,
    size_bytes: u64,

    pub fn computeSha256(data: []const u8) [64]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }
};

pub const ConfigurationMetadata = struct {
    profile_id: []const u8,
    profile_name: []const u8,
    target_count: usize = 0,
    ports_count: usize = 0,
    rate_limit_rps: u32 = 0,
    timeout_ms: u64 = 0,
};

pub const ReportManifest = struct {
    schema_version: u32 = MANIFEST_SCHEMA_VERSION,
    tool_name: []const u8 = CURRENT_TOOL_NAME,
    tool_version: []const u8 = CURRENT_TOOL_VERSION,
    manifest_id: []const u8,
    assessment_id: []const u8,
    created_at_ms: i64,
    configuration: ConfigurationMetadata,
    artifacts: []ArtifactEntry,
    manifest_hash: [64]u8,
    limitations_notice: []const u8 = HASH_LIMITATIONS_NOTICE,

    pub fn deinit(self: *ReportManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.manifest_id);
        allocator.free(self.assessment_id);
        allocator.free(self.configuration.profile_id);
        allocator.free(self.configuration.profile_name);
        for (self.artifacts) |art| {
            allocator.free(art.path);
            allocator.free(art.hash_algo);
        }
        allocator.free(self.artifacts);
    }

    /// Computes canonical SHA-256 hash across manifest metadata and artifact digests
    pub fn computeManifestHash(
        assessment_id: []const u8,
        profile_id: []const u8,
        artifacts: []const ArtifactEntry,
    ) [64]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("wirescope-report-manifest-v1:");
        hasher.update(assessment_id);
        hasher.update(":");
        hasher.update(profile_id);
        hasher.update(":");

        for (artifacts) |art| {
            hasher.update(art.path);
            hasher.update("=");
            hasher.update(&art.hash);
            hasher.update(";");
        }

        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        return std.fmt.bytesToHex(digest, .lower);
    }

    /// Serializes the manifest into a formatted JSON string
    pub fn toJson(self: *const ReportManifest, allocator: std.mem.Allocator) ![]const u8 {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const writer = buf.writer();

        try writer.print(
            \\{{
            \\  "schema_version": {d},
            \\  "tool_name": "{s}",
            \\  "tool_version": "{s}",
            \\  "manifest_id": "{s}",
            \\  "assessment_id": "{s}",
            \\  "created_at_ms": {d},
            \\  "configuration": {{
            \\    "profile_id": "{s}",
            \\    "profile_name": "{s}",
            \\    "target_count": {d},
            \\    "ports_count": {d},
            \\    "rate_limit_rps": {d},
            \\    "timeout_ms": {d}
            \\  }},
            \\  "manifest_hash": "{s}",
            \\  "limitations_notice": "{s}",
            \\  "artifacts": [
        , .{
            self.schema_version,
            self.tool_name,
            self.tool_version,
            self.manifest_id,
            self.assessment_id,
            self.created_at_ms,
            self.configuration.profile_id,
            self.configuration.profile_name,
            self.configuration.target_count,
            self.configuration.ports_count,
            self.configuration.rate_limit_rps,
            self.configuration.timeout_ms,
            &self.manifest_hash,
            self.limitations_notice,
        });

        for (self.artifacts, 0..) |art, idx| {
            try writer.print(
                \\
                \\    {{
                \\      "path": "{s}",
                \\      "artifact_type": "{s}",
                \\      "hash_algo": "{s}",
                \\      "hash": "{s}",
                \\      "size_bytes": {d}
                \\    }}{s}
            , .{
                art.path,
                art.artifact_type.toSlice(),
                art.hash_algo,
                &art.hash,
                art.size_bytes,
                if (idx + 1 < self.artifacts.len) "," else "",
            });
        }

        try writer.print("\n  ]\n}}\n", .{});
        return buf.toOwnedSlice();
    }

    /// Parses and validates a JSON string into a ReportManifest
    pub fn parseFromJson(allocator: std.mem.Allocator, json_str: []const u8) !ReportManifest {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
            return ManifestError.ManifestCorrupt;
        };
        defer parsed.deinit();

        if (parsed.value != .object) return ManifestError.InvalidManifestSchema;
        const root = parsed.value.object;

        const sv_val = root.get("schema_version") orelse return ManifestError.InvalidManifestSchema;
        if (sv_val != .integer) return ManifestError.InvalidManifestSchema;
        const schema_v: u32 = @intCast(sv_val.integer);
        if (schema_v > MANIFEST_SCHEMA_VERSION) return ManifestError.UnsupportedFutureManifestVersion;

        const man_id_val = root.get("manifest_id") orelse return ManifestError.InvalidManifestSchema;
        if (man_id_val != .string) return ManifestError.InvalidManifestSchema;

        const asm_id_val = root.get("assessment_id") orelse return ManifestError.InvalidManifestSchema;
        if (asm_id_val != .string) return ManifestError.InvalidManifestSchema;

        const cat_val = root.get("created_at_ms") orelse return ManifestError.InvalidManifestSchema;
        if (cat_val != .integer) return ManifestError.InvalidManifestSchema;

        const mhash_val = root.get("manifest_hash") orelse return ManifestError.InvalidManifestSchema;
        if (mhash_val != .string or mhash_val.string.len != 64) return ManifestError.InvalidManifestSchema;

        var mhash: [64]u8 = undefined;
        @memcpy(&mhash, mhash_val.string[0..64]);

        // Configuration
        const cfg_val = root.get("configuration") orelse return ManifestError.InvalidManifestSchema;
        if (cfg_val != .object) return ManifestError.InvalidManifestSchema;
        const cfg_obj = cfg_val.object;

        const prof_id = if (cfg_obj.get("profile_id")) |p| (if (p == .string) p.string else "unknown") else "unknown";
        const prof_name = if (cfg_obj.get("profile_name")) |p| (if (p == .string) p.string else "unknown") else "unknown";
        const tgt_count: usize = if (cfg_obj.get("target_count")) |t| (if (t == .integer and t.integer >= 0) @intCast(t.integer) else 0) else 0;
        const prt_count: usize = if (cfg_obj.get("ports_count")) |p| (if (p == .integer and p.integer >= 0) @intCast(p.integer) else 0) else 0;
        const rl_rps: u32 = if (cfg_obj.get("rate_limit_rps")) |r| (if (r == .integer and r.integer >= 0) @intCast(r.integer) else 0) else 0;
        const to_ms: u64 = if (cfg_obj.get("timeout_ms")) |t| (if (t == .integer and t.integer >= 0) @intCast(t.integer) else 0) else 0;

        // Artifacts
        const arts_val = root.get("artifacts") orelse return ManifestError.InvalidManifestSchema;
        if (arts_val != .array) return ManifestError.InvalidManifestSchema;
        const arts_arr = arts_val.array;

        var artifacts_list = std.ArrayList(ArtifactEntry).init(allocator);
        errdefer {
            for (artifacts_list.items) |art| {
                allocator.free(art.path);
                allocator.free(art.hash_algo);
            }
            artifacts_list.deinit();
        }

        for (arts_arr.items) |item| {
            if (item != .object) return ManifestError.InvalidManifestSchema;
            const obj = item.object;

            const path_v = obj.get("path") orelse return ManifestError.InvalidManifestSchema;
            if (path_v != .string) return ManifestError.InvalidManifestSchema;

            const atype_v = obj.get("artifact_type") orelse return ManifestError.InvalidManifestSchema;
            if (atype_v != .string) return ManifestError.InvalidManifestSchema;

            const algo_v = if (obj.get("hash_algo")) |a| (if (a == .string) a.string else DEFAULT_HASH_ALGO) else DEFAULT_HASH_ALGO;

            const hash_v = obj.get("hash") orelse return ManifestError.InvalidManifestSchema;
            if (hash_v != .string or hash_v.string.len != 64) return ManifestError.InvalidManifestSchema;

            const size_v = obj.get("size_bytes") orelse return ManifestError.InvalidManifestSchema;
            if (size_v != .integer or size_v.integer < 0) return ManifestError.InvalidManifestSchema;

            var art_hash: [64]u8 = undefined;
            @memcpy(&art_hash, hash_v.string[0..64]);

            try artifacts_list.append(.{
                .path = try allocator.dupe(u8, path_v.string),
                .artifact_type = ArtifactType.fromSlice(atype_v.string),
                .hash_algo = try allocator.dupe(u8, algo_v),
                .hash = art_hash,
                .size_bytes = @intCast(size_v.integer),
            });
        }

        return ReportManifest{
            .schema_version = schema_v,
            .manifest_id = try allocator.dupe(u8, man_id_val.string),
            .assessment_id = try allocator.dupe(u8, asm_id_val.string),
            .created_at_ms = cat_val.integer,
            .configuration = .{
                .profile_id = try allocator.dupe(u8, prof_id),
                .profile_name = try allocator.dupe(u8, prof_name),
                .target_count = tgt_count,
                .ports_count = prt_count,
                .rate_limit_rps = rl_rps,
                .timeout_ms = to_ms,
            },
            .artifacts = try artifacts_list.toOwnedSlice(),
            .manifest_hash = mhash,
        };
    }
};

// -----------------------------------------------------------------------------
// Manifest Verification Engine
// -----------------------------------------------------------------------------

pub const ArtifactStatus = enum {
    intact,
    modified,
    missing,
    unreadable,
    path_traversal_rejected,

    pub fn toSlice(self: ArtifactStatus) []const u8 {
        return switch (self) {
            .intact => "intact",
            .modified => "modified",
            .missing => "missing",
            .unreadable => "unreadable",
            .path_traversal_rejected => "path_traversal_rejected",
        };
    }
};

pub const ArtifactVerification = struct {
    path: []const u8,
    status: ArtifactStatus,
    expected_hash: [64]u8,
    actual_hash: ?[64]u8 = null,
    expected_size: u64,
    actual_size: ?u64 = null,
    error_message: ?[]const u8 = null,

    pub fn deinit(self: *ArtifactVerification, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.error_message) |msg| allocator.free(msg);
    }
};

pub const ManifestVerificationResult = struct {
    allocator: std.mem.Allocator,
    manifest_id: []const u8,
    assessment_id: []const u8,
    is_valid: bool,
    manifest_hash_valid: bool,
    manifest_error: ?[]const u8 = null,
    total_artifacts: usize,
    intact_count: usize,
    modified_count: usize,
    missing_count: usize,
    unreadable_count: usize,
    artifacts: []ArtifactVerification,
    limitations_notice: []const u8 = HASH_LIMITATIONS_NOTICE,

    pub fn deinit(self: *ManifestVerificationResult) void {
        self.allocator.free(self.manifest_id);
        self.allocator.free(self.assessment_id);
        if (self.manifest_error) |err| self.allocator.free(err);
        for (self.artifacts) |*art| {
            art.deinit(self.allocator);
        }
        self.allocator.free(self.artifacts);
    }

    pub fn renderTerminal(self: *const ManifestVerificationResult, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE REPORT INTEGRITY VERIFICATION
            \\================================================================================
            \\Manifest ID:       {s}
            \\Assessment ID:     {s}
            \\Manifest Integrity: {s}
            \\Total Artifacts:   {d}
            \\  Intact:          {d}
            \\  Modified:        {d}
            \\  Missing:         {d}
            \\  Unreadable:      {d}
            \\Overall Status:    {s}
            \\--------------------------------------------------------------------------------
            \\Artifact Details:
            \\
        , .{
            self.manifest_id,
            self.assessment_id,
            if (self.manifest_hash_valid) "VALID (Digest verified)" else "COMPROMISED (Digest mismatch)",
            self.total_artifacts,
            self.intact_count,
            self.modified_count,
            self.missing_count,
            self.unreadable_count,
            if (self.is_valid) "PASS (All artifacts intact)" else "FAIL (Tampered, modified, or missing artifacts detected)",
        });

        for (self.artifacts) |art| {
            const status_icon = switch (art.status) {
                .intact => "[PASS]",
                .modified => "[MODIFIED]",
                .missing => "[MISSING]",
                .unreadable => "[ERROR]",
                .path_traversal_rejected => "[BLOCKED]",
            };
            try writer.print("  {s:9} {s} ({s})\n", .{ status_icon, art.path, art.status.toSlice() });
            if (art.status == .modified) {
                try writer.print("            Expected SHA-256: {s}\n", .{&art.expected_hash});
                if (art.actual_hash) |h| {
                    try writer.print("            Actual SHA-256:   {s}\n", .{&h});
                }
            } else if (art.error_message) |msg| {
                try writer.print("            Reason: {s}\n", .{msg});
            }
        }

        try writer.print(
            \\--------------------------------------------------------------------------------
            \\LIMITATIONS & SECURITY NOTICE:
            \\  {s}
            \\================================================================================
            \\
        , .{self.limitations_notice});
    }

    pub fn renderJson(self: *const ManifestVerificationResult, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"manifest_verification","schema_version":1,"manifest_id":"{s}","assessment_id":"{s}","is_valid":{s},"manifest_hash_valid":{s},"summary":{{"total":{d},"intact":{d},"modified":{d},"missing":{d},"unreadable":{d}}},"limitations_notice":"{s}","artifacts":[
        , .{
            self.manifest_id,
            self.assessment_id,
            if (self.is_valid) "true" else "false",
            if (self.manifest_hash_valid) "true" else "false",
            self.total_artifacts,
            self.intact_count,
            self.modified_count,
            self.missing_count,
            self.unreadable_count,
            self.limitations_notice,
        });

        for (self.artifacts, 0..) |art, idx| {
            try writer.print(
                \\{{"path":"{s}","status":"{s}","expected_hash":"{s}","actual_hash":
            , .{
                art.path,
                art.status.toSlice(),
                &art.expected_hash,
            });
            if (art.actual_hash) |h| {
                try writer.print("\"{s}\"", .{&h});
            } else {
                try writer.writeAll("null");
            }
            try writer.print(",\"expected_size\":{d},\"actual_size\":", .{art.expected_size});
            if (art.actual_size) |s| {
                try writer.print("{d}", .{s});
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll("}");
            if (idx + 1 < self.artifacts.len) {
                try writer.writeAll(",");
            }
        }

        try writer.writeAll("]}\n");
    }

    pub fn renderMarkdown(self: *const ManifestVerificationResult, writer: anytype) !void {
        try writer.print(
            \\# WireScope Report Integrity Verification
            \\
            \\**Manifest ID:** `{s}`  
            \\**Assessment ID:** `{s}`  
            \\**Manifest Digest:** `{s}`  
            \\**Overall Status:** **{s}**  
            \\
            \\## Summary
            \\
            \\| Metric | Count |
            \\| :--- | :---: |
            \\| Total Artifacts | {d} |
            \\| Intact (Verified) | {d} |
            \\| Modified (Tampered) | {d} |
            \\| Missing Artifacts | {d} |
            \\| Unreadable / Errors | {d} |
            \\
            \\## Artifact Verification Details
            \\
            \\| Artifact Path | Status | Expected SHA-256 | Actual SHA-256 |
            \\| :--- | :---: | :--- | :--- |
            \\
        , .{
            self.manifest_id,
            self.assessment_id,
            if (self.manifest_hash_valid) "Valid" else "Tampered / Invalid",
            if (self.is_valid) "PASSED" else "FAILED",
            self.total_artifacts,
            self.intact_count,
            self.modified_count,
            self.missing_count,
            self.unreadable_count,
        });

        for (self.artifacts) |art| {
            const badge = switch (art.status) {
                .intact => "PASS",
                .modified => "MODIFIED",
                .missing => "MISSING",
                .unreadable => "ERROR",
                .path_traversal_rejected => "BLOCKED",
            };
            const actual_str = if (art.actual_hash) |h| &h else "-";
            try writer.print("| `{s}` | `{s}` | `{s:.16}...` | `{s:.16}...` |\n", .{
                art.path,
                badge,
                &art.expected_hash,
                actual_str,
            });
        }

        try writer.print(
            \\
            \\> [!WARNING]
            \\> **Cryptographic Limitations Notice:**  
            \\> {s}
            \\
        , .{self.limitations_notice});
    }
};

/// Validates that an artifact path is safe and does not escape the artifacts sandbox
pub fn isSafeContainedPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.mem.indexOf(u8, path, "..") != null) return false;
    if (std.mem.startsWith(u8, path, "/") or std.mem.startsWith(u8, path, "\\")) return false;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return false;
    return true;
}

/// Verifies a ReportManifest against artifacts located in the specified directory
pub fn verifyManifest(
    allocator: std.mem.Allocator,
    manifest: *const ReportManifest,
    artifacts_dir: []const u8,
) !ManifestVerificationResult {
    // 1. Verify Manifest Integrity Hash itself
    const computed_mhash = ReportManifest.computeManifestHash(
        manifest.assessment_id,
        manifest.configuration.profile_id,
        manifest.artifacts,
    );
    const mhash_valid = std.mem.eql(u8, &computed_mhash, &manifest.manifest_hash);

    var verifications = std.ArrayList(ArtifactVerification).init(allocator);
    errdefer {
        for (verifications.items) |*v| v.deinit(allocator);
        verifications.deinit();
    }

    var intact: usize = 0;
    var modified: usize = 0;
    var missing: usize = 0;
    var unreadable: usize = 0;

    for (manifest.artifacts) |art| {
        // Enforce path containment sandbox
        if (!isSafeContainedPath(art.path)) {
            try verifications.append(.{
                .path = try allocator.dupe(u8, art.path),
                .status = .path_traversal_rejected,
                .expected_hash = art.hash,
                .actual_hash = null,
                .expected_size = art.size_bytes,
                .actual_size = null,
                .error_message = try allocator.dupe(u8, "Path traversal sequence rejected by sandbox"),
            });
            unreadable += 1;
            continue;
        }

        // Build full path
        const full_path = std.fs.path.join(allocator, &[_][]const u8{ artifacts_dir, art.path }) catch {
            return ManifestError.OutOfMemory;
        };
        defer allocator.free(full_path);

        // Check file existence and read
        const file = std.fs.cwd().openFile(full_path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                try verifications.append(.{
                    .path = try allocator.dupe(u8, art.path),
                    .status = .missing,
                    .expected_hash = art.hash,
                    .actual_hash = null,
                    .expected_size = art.size_bytes,
                    .actual_size = null,
                    .error_message = try allocator.dupe(u8, "Artifact file not found on disk"),
                });
                missing += 1;
            } else {
                try verifications.append(.{
                    .path = try allocator.dupe(u8, art.path),
                    .status = .unreadable,
                    .expected_hash = art.hash,
                    .actual_hash = null,
                    .expected_size = art.size_bytes,
                    .actual_size = null,
                    .error_message = try std.fmt.allocPrint(allocator, "File open error: {s}", .{@errorName(err)}),
                });
                unreadable += 1;
            }
            continue;
        };
        defer file.close();

        const stat = file.stat() catch |err| {
            try verifications.append(.{
                .path = try allocator.dupe(u8, art.path),
                .status = .unreadable,
                .expected_hash = art.hash,
                .actual_hash = null,
                .expected_size = art.size_bytes,
                .actual_size = null,
                .error_message = try std.fmt.allocPrint(allocator, "File stat error: {s}", .{@errorName(err)}),
            });
            unreadable += 1;
            continue;
        };

        const content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch |err| {
            try verifications.append(.{
                .path = try allocator.dupe(u8, art.path),
                .status = .unreadable,
                .expected_hash = art.hash,
                .actual_hash = null,
                .expected_size = art.size_bytes,
                .actual_size = stat.size,
                .error_message = try std.fmt.allocPrint(allocator, "File read error: {s}", .{@errorName(err)}),
            });
            unreadable += 1;
            continue;
        };
        defer allocator.free(content);

        const actual_hash = ArtifactEntry.computeSha256(content);
        const is_hash_match = std.mem.eql(u8, &actual_hash, &art.hash);
        const is_size_match = (stat.size == art.size_bytes);

        if (is_hash_match and is_size_match) {
            try verifications.append(.{
                .path = try allocator.dupe(u8, art.path),
                .status = .intact,
                .expected_hash = art.hash,
                .actual_hash = actual_hash,
                .expected_size = art.size_bytes,
                .actual_size = stat.size,
                .error_message = null,
            });
            intact += 1;
        } else {
            try verifications.append(.{
                .path = try allocator.dupe(u8, art.path),
                .status = .modified,
                .expected_hash = art.hash,
                .actual_hash = actual_hash,
                .expected_size = art.size_bytes,
                .actual_size = stat.size,
                .error_message = try allocator.dupe(u8, "SHA-256 digest or size does not match manifest record"),
            });
            modified += 1;
        }
    }

    const overall_valid = mhash_valid and (modified == 0) and (missing == 0) and (unreadable == 0);

    return ManifestVerificationResult{
        .allocator = allocator,
        .manifest_id = try allocator.dupe(u8, manifest.manifest_id),
        .assessment_id = try allocator.dupe(u8, manifest.assessment_id),
        .is_valid = overall_valid,
        .manifest_hash_valid = mhash_valid,
        .manifest_error = if (!mhash_valid) try allocator.dupe(u8, "Manifest canonical SHA-256 hash mismatch") else null,
        .total_artifacts = manifest.artifacts.len,
        .intact_count = intact,
        .modified_count = modified,
        .missing_count = missing,
        .unreadable_count = unreadable,
        .artifacts = try verifications.toOwnedSlice(),
    };
}

pub const ArtifactFileSpec = struct {
    name: []const u8,
    atype: ArtifactType,
};

/// Helper to generate a manifest from on-disk artifacts
pub fn generateManifest(
    allocator: std.mem.Allocator,
    assessment_id: []const u8,
    config: ConfigurationMetadata,
    artifacts_dir: []const u8,
    artifact_names: []const ArtifactFileSpec,
) !ReportManifest {
    var entries = std.ArrayList(ArtifactEntry).init(allocator);
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.path);
            allocator.free(e.hash_algo);
        }
        entries.deinit();
    }

    for (artifact_names) |item| {
        if (!isSafeContainedPath(item.name)) return ManifestError.PathTraversalEscape;

        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ artifacts_dir, item.name });
        defer allocator.free(full_path);

        const file = std.fs.cwd().openFile(full_path, .{}) catch return ManifestError.IoError;
        defer file.close();

        const stat = file.stat() catch return ManifestError.IoError;
        const content = file.readToEndAlloc(allocator, 50 * 1024 * 1024) catch return ManifestError.IoError;
        defer allocator.free(content);

        const hash = ArtifactEntry.computeSha256(content);

        try entries.append(.{
            .path = try allocator.dupe(u8, item.name),
            .artifact_type = item.atype,
            .hash_algo = try allocator.dupe(u8, DEFAULT_HASH_ALGO),
            .hash = hash,
            .size_bytes = stat.size,
        });
    }

    const mhash = ReportManifest.computeManifestHash(assessment_id, config.profile_id, entries.items);
    var man_id_buf: [128]u8 = undefined;
    const man_id = try std.fmt.bufPrint(&man_id_buf, "mnf-{s}", .{assessment_id});

    return ReportManifest{
        .schema_version = MANIFEST_SCHEMA_VERSION,
        .manifest_id = try allocator.dupe(u8, man_id),
        .assessment_id = try allocator.dupe(u8, assessment_id),
        .created_at_ms = std.time.milliTimestamp(),
        .configuration = .{
            .profile_id = try allocator.dupe(u8, config.profile_id),
            .profile_name = try allocator.dupe(u8, config.profile_name),
            .target_count = config.target_count,
            .ports_count = config.ports_count,
            .rate_limit_rps = config.rate_limit_rps,
            .timeout_ms = config.timeout_ms,
        },
        .artifacts = try entries.toOwnedSlice(),
        .manifest_hash = mhash,
    };
}

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Phase 11.3 Acceptance Criteria)
// -----------------------------------------------------------------------------

test "manifest: versioned manifest schema serialization and deserialization" {
    const allocator = testing.allocator;

    var artifacts = try allocator.alloc(ArtifactEntry, 2);
    artifacts[0] = .{
        .path = try allocator.dupe(u8, "report.json"),
        .artifact_type = .json_report,
        .hash_algo = try allocator.dupe(u8, "sha256"),
        .hash = ArtifactEntry.computeSha256("{\"report\":\"sample\"}"),
        .size_bytes = 19,
    };
    artifacts[1] = .{
        .path = try allocator.dupe(u8, "report.md"),
        .artifact_type = .markdown_report,
        .hash_algo = try allocator.dupe(u8, "sha256"),
        .hash = ArtifactEntry.computeSha256("# Sample Report Markdown"),
        .size_bytes = 24,
    };

    const mhash = ReportManifest.computeManifestHash("asm-201", "local-sec-audit", artifacts);

    var manifest = ReportManifest{
        .schema_version = 1,
        .manifest_id = try allocator.dupe(u8, "mnf-asm-201"),
        .assessment_id = try allocator.dupe(u8, "asm-201"),
        .created_at_ms = 1710000000000,
        .configuration = .{
            .profile_id = try allocator.dupe(u8, "local-sec-audit"),
            .profile_name = try allocator.dupe(u8, "Local Security Audit"),
            .target_count = 1,
            .ports_count = 2,
            .rate_limit_rps = 10,
            .timeout_ms = 5000,
        },
        .artifacts = artifacts,
        .manifest_hash = mhash,
    };
    defer manifest.deinit(allocator);

    const json = try manifest.toJson(allocator);
    defer allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"schema_version\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"manifest_id\": \"mnf-asm-201\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"assessment_id\": \"asm-201\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"report.json\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"report.md\"") != null);

    // Parse back
    var parsed = try ReportManifest.parseFromJson(allocator, json);
    defer parsed.deinit(allocator);

    try testing.expectEqual(@as(u32, 1), parsed.schema_version);
    try testing.expectEqualStrings("mnf-asm-201", parsed.manifest_id);
    try testing.expectEqualStrings("asm-201", parsed.assessment_id);
    try testing.expectEqualStrings("local-sec-audit", parsed.configuration.profile_id);
    try testing.expectEqual(@as(usize, 2), parsed.artifacts.len);
    try testing.expectEqualStrings("report.json", parsed.artifacts[0].path);
    try testing.expectEqualStrings("report.md", parsed.artifacts[1].path);
    try testing.expectEqualStrings(&manifest.manifest_hash, &parsed.manifest_hash);
}

test "manifest: detects intact, modified, and missing artifacts accurately" {
    const allocator = testing.allocator;
    const test_dir = "test_manifest_verification";
    defer std.fs.cwd().deleteTree(test_dir) catch {};

    try std.fs.cwd().makePath(test_dir);

    // Create 3 artifacts on disk
    const path1 = try std.fs.path.join(allocator, &[_][]const u8{ test_dir, "report.json" });
    defer allocator.free(path1);
    try std.fs.cwd().writeFile(.{ .sub_path = path1, .data = "{\"result\":\"pass\",\"count\":4}" });

    const path2 = try std.fs.path.join(allocator, &[_][]const u8{ test_dir, "report.md" });
    defer allocator.free(path2);
    try std.fs.cwd().writeFile(.{ .sub_path = path2, .data = "# Assessment Markdown Summary" });

    const path3 = try std.fs.path.join(allocator, &[_][]const u8{ test_dir, "findings.json" });
    defer allocator.free(path3);
    try std.fs.cwd().writeFile(.{ .sub_path = path3, .data = "[]" });

    // Generate manifest
    const art_items = [_]ArtifactFileSpec{
        .{ .name = "report.json", .atype = .json_report },
        .{ .name = "report.md", .atype = .markdown_report },
        .{ .name = "findings.json", .atype = .findings },
    };

    var manifest = try generateManifest(
        allocator,
        "asm-intact-test",
        .{ .profile_id = "test-prof", .profile_name = "Test Profile" },
        test_dir,
        &art_items,
    );
    defer manifest.deinit(allocator);

    // Scenario 1: All artifacts intact
    {
        var result = try verifyManifest(allocator, &manifest, test_dir);
        defer result.deinit();

        try testing.expect(result.is_valid);
        try testing.expect(result.manifest_hash_valid);
        try testing.expectEqual(@as(usize, 3), result.total_artifacts);
        try testing.expectEqual(@as(usize, 3), result.intact_count);
        try testing.expectEqual(@as(usize, 0), result.modified_count);
        try testing.expectEqual(@as(usize, 0), result.missing_count);
    }

    // Scenario 2: Tamper / modify report.md
    {
        try std.fs.cwd().writeFile(.{ .sub_path = path2, .data = "# Tampered Content by Attacker" });

        var result = try verifyManifest(allocator, &manifest, test_dir);
        defer result.deinit();

        try testing.expect(!result.is_valid); // Must detect tampering!
        try testing.expectEqual(@as(usize, 2), result.intact_count);
        try testing.expectEqual(@as(usize, 1), result.modified_count);
        try testing.expectEqual(@as(usize, 0), result.missing_count);

        // Verify the modified artifact details
        for (result.artifacts) |art| {
            if (std.mem.eql(u8, art.path, "report.md")) {
                try testing.expectEqual(ArtifactStatus.modified, art.status);
                try testing.expect(art.actual_hash != null);
                try testing.expect(!std.mem.eql(u8, &art.expected_hash, &art.actual_hash.?));
            }
        }
    }

    // Scenario 3: Delete findings.json (missing artifact)
    {
        try std.fs.cwd().deleteFile(path3);

        var result = try verifyManifest(allocator, &manifest, test_dir);
        defer result.deinit();

        try testing.expect(!result.is_valid); // Must detect missing!
        try testing.expectEqual(@as(usize, 1), result.intact_count);
        try testing.expectEqual(@as(usize, 1), result.modified_count);
        try testing.expectEqual(@as(usize, 1), result.missing_count);

        for (result.artifacts) |art| {
            if (std.mem.eql(u8, art.path, "findings.json")) {
                try testing.expectEqual(ArtifactStatus.missing, art.status);
            }
        }
    }
}

test "manifest: invalid manifests, future schema versions, and malformed inputs fail safely" {
    const allocator = testing.allocator;

    // Malformed JSON
    try testing.expectError(ManifestError.ManifestCorrupt, ReportManifest.parseFromJson(allocator, "{ not json"));

    // Future unsupported schema version
    const future_json = "{\"schema_version\": 99, \"manifest_id\": \"m1\", \"assessment_id\": \"a1\"}";
    try testing.expectError(ManifestError.UnsupportedFutureManifestVersion, ReportManifest.parseFromJson(allocator, future_json));

    // Missing required fields
    const missing_fields_json = "{\"schema_version\": 1}";
    try testing.expectError(ManifestError.InvalidManifestSchema, ReportManifest.parseFromJson(allocator, missing_fields_json));
}

test "manifest: path traversal in artifact paths is strictly rejected" {
    try testing.expect(!isSafeContainedPath("../outside.txt"));
    try testing.expect(!isSafeContainedPath("..\\outside.txt"));
    try testing.expect(!isSafeContainedPath("/etc/passwd"));
    try testing.expect(!isSafeContainedPath("C:\\Windows\\cmd.exe"));
    try testing.expect(!isSafeContainedPath(""));
    try testing.expect(isSafeContainedPath("reports/assessment.json"));
    try testing.expect(isSafeContainedPath("findings.json"));
}

test "manifest: output rendering formats include hash limitations notice" {
    const allocator = testing.allocator;

    var arts = try allocator.alloc(ArtifactVerification, 1);
    arts[0] = .{
        .path = try allocator.dupe(u8, "report.json"),
        .status = .intact,
        .expected_hash = ArtifactEntry.computeSha256("test"),
        .actual_hash = ArtifactEntry.computeSha256("test"),
        .expected_size = 4,
        .actual_size = 4,
    };

    var result = ManifestVerificationResult{
        .allocator = allocator,
        .manifest_id = try allocator.dupe(u8, "mnf-test"),
        .assessment_id = try allocator.dupe(u8, "asm-test"),
        .is_valid = true,
        .manifest_hash_valid = true,
        .total_artifacts = 1,
        .intact_count = 1,
        .modified_count = 0,
        .missing_count = 0,
        .unreadable_count = 0,
        .artifacts = arts,
    };
    defer result.deinit();

    // 1. Terminal render
    var term_buf: [4096]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try result.renderTerminal(term_fbs.writer());
    const term_out = term_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, term_out, "WIRESCOPE REPORT INTEGRITY VERIFICATION") != null);
    try testing.expect(std.mem.indexOf(u8, term_out, "LIMITATIONS & SECURITY NOTICE") != null);
    try testing.expect(std.mem.indexOf(u8, term_out, "does NOT prove author identity") != null);

    // 2. JSON render
    var json_buf: [4096]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try result.renderJson(json_fbs.writer());
    const json_out = json_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_out, "\"report_type\":\"manifest_verification\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"limitations_notice\":") != null);

    // 3. Markdown render
    var md_buf: [4096]u8 = undefined;
    var md_fbs = std.io.fixedBufferStream(&md_buf);
    try result.renderMarkdown(md_fbs.writer());
    const md_out = md_fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, md_out, "# WireScope Report Integrity Verification") != null);
    try testing.expect(std.mem.indexOf(u8, md_out, "Cryptographic Limitations Notice:") != null);
}
