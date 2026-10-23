const std = @import("std");
const testing = std.testing;

pub const schema = @import("schema.zig");
pub const json = @import("json.zig");
pub const redact = @import("redact.zig");
pub const markdown = @import("markdown.zig");
pub const terminal = @import("terminal.zig");
pub const parser = @import("parser.zig");
pub const writer = @import("writer.zig");

pub const ReportFormat = enum {
    terminal,
    json,
    markdown,

    pub fn fromString(str: []const u8) ?ReportFormat {
        if (std.mem.eql(u8, str, "terminal") or std.mem.eql(u8, str, "term") or std.mem.eql(u8, str, "txt") or std.mem.eql(u8, str, "text")) {
            return .terminal;
        } else if (std.mem.eql(u8, str, "json")) {
            return .json;
        } else if (std.mem.eql(u8, str, "markdown") or std.mem.eql(u8, str, "md")) {
            return .markdown;
        }
        return null;
    }
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

// Redaction re-exports
pub const RedactionConfig = redact.RedactionConfig;
pub const REDACTION_WARNING_NOTICE = redact.REDACTION_WARNING_NOTICE;
pub const REDACTION_DISCLAIMER_MARKDOWN = redact.REDACTION_DISCLAIMER_MARKDOWN;
pub const redactText = redact.redactText;
pub const redactReportData = redact.redactReportData;

// Markdown re-exports
pub const MarkdownOptions = markdown.MarkdownOptions;
pub const renderMarkdown = markdown.renderMarkdown;
pub const renderMarkdownToString = markdown.renderMarkdownToString;

// Terminal re-exports
pub const TerminalOptions = terminal.TerminalOptions;
pub const renderTerminal = terminal.renderTerminal;
pub const renderTerminalToString = terminal.renderTerminalToString;

// Parser re-exports
pub const ParsedReport = parser.ParsedReport;
pub const parseReportFromJson = parser.parseReportFromJson;

// Safe Writer re-exports
pub const SafeWriteError = writer.SafeWriteError;
pub const safeWriteReportFile = writer.safeWriteReportFile;

test "reporting definitions compile" {
    _ = schema;
    _ = json;
    _ = redact;
    _ = markdown;
    _ = terminal;
    _ = parser;
    _ = writer;

    const config = ReportConfig{};
    try testing.expectEqual(ReportFormat.terminal, config.format);
}
