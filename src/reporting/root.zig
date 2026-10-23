const std = @import("std");
const testing = std.testing;

pub const schema = @import("schema.zig");
pub const json = @import("json.zig");

pub const ReportFormat = enum {
    terminal,
    json,
    markdown,
};

pub const ReportConfig = struct {
    format: ReportFormat = .terminal,
    redact_sensitive: bool = true,
};

// Re-exports from schema
pub const REPORT_SCHEMA_VERSION = schema.REPORT_SCHEMA_VERSION;
pub const REPORT_SCHEMA_ID = schema.REPORT_SCHEMA_ID;
pub const REPORT_DOCUMENT_TYPE = schema.REPORT_DOCUMENT_TYPE;
pub const SchemaValidationError = schema.SchemaValidationError;
pub const validateReportJson = schema.validateReportJson;

// Re-exports from json
pub const CheckItem = json.CheckItem;
pub const DnsObsItem = json.DnsObsItem;
pub const TcpObsItem = json.TcpObsItem;
pub const TlsObsItem = json.TlsObsItem;
pub const HttpObsItem = json.HttpObsItem;
pub const ListenerObsItem = json.ListenerObsItem;
pub const AssetItem = json.AssetItem;
pub const FindingItem = json.FindingItem;
pub const PolicyResultItem = json.PolicyResultItem;
pub const LimitationItem = json.LimitationItem;
pub const TaskFailureItem = json.TaskFailureItem;
pub const AssessmentReportData = json.AssessmentReportData;
pub const serializeReport = json.serializeReport;
pub const normalizeJsonReport = json.normalizeJsonReport;

// Sorters
pub const sortTargets = json.sortTargets;
pub const sortPorts = json.sortPorts;
pub const sortFindings = json.sortFindings;
pub const sortChecks = json.sortChecks;
pub const sortPolicyResults = json.sortPolicyResults;
pub const sortDnsObservations = json.sortDnsObservations;
pub const sortTcpObservations = json.sortTcpObservations;
pub const sortTlsObservations = json.sortTlsObservations;
pub const sortHttpObservations = json.sortHttpObservations;
pub const sortListenerObservations = json.sortListenerObservations;
pub const sortLimitations = json.sortLimitations;

test "reporting definitions compile" {
    _ = schema;
    _ = json;

    const config = ReportConfig{};
    try testing.expectEqual(ReportFormat.terminal, config.format);
}
