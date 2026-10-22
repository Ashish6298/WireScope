const std = @import("std");
const testing = std.testing;

pub const fixtures = @import("fixtures.zig");
pub const http_audit = @import("http_audit.zig");
pub const exposure_audit = @import("exposure_audit.zig");

// Re-export public types and functions
pub const SameSitePolicy = http_audit.SameSitePolicy;
pub const HttpCookie = http_audit.HttpCookie;
pub const HttpAuditFinding = http_audit.HttpAuditFinding;
pub const HttpAuditConfig = http_audit.HttpAuditConfig;
pub const ParsedHttpResponse = http_audit.ParsedHttpResponse;
pub const parseHttpResponse = http_audit.parseHttpResponse;
pub const HttpAuditResult = http_audit.HttpAuditResult;
pub const HttpAuditConnector = http_audit.HttpAuditConnector;
pub const MockHttpAuditConnector = http_audit.MockHttpAuditConnector;
pub const evaluateHttpSecurityRules = http_audit.evaluateHttpSecurityRules;
pub const executeHttpAudit = http_audit.executeHttpAudit;

// Re-export exposure audit types and functions (Phase 9.2)
pub const BindingPolicy = exposure_audit.BindingPolicy;
pub const ExpectedServicePolicy = exposure_audit.ExpectedServicePolicy;
pub const LocalExposurePolicy = exposure_audit.LocalExposurePolicy;
pub const LocalExposureFinding = exposure_audit.LocalExposureFinding;
pub const LocalExposureAuditResult = exposure_audit.LocalExposureAuditResult;
pub const ListenerInspector = exposure_audit.ListenerInspector;
pub const RealListenerInspector = exposure_audit.RealListenerInspector;
pub const MockListenerInspector = exposure_audit.MockListenerInspector;
pub const auditLocalExposure = exposure_audit.auditLocalExposure;

test "audit module root re-exports compile cleanly" {
    _ = fixtures;
    _ = http_audit;
    _ = exposure_audit;
}
