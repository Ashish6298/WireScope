const std = @import("std");
const testing = std.testing;
const audit = @import("../audit/root.zig");

pub const PolicyOutcome = audit.RuleOutcome;
pub const Rule = audit.VersionedRule;
pub const RuleCategory = audit.RuleCategory;
pub const RuleOutcome = audit.RuleOutcome;
pub const RuleValidationError = audit.RuleValidationError;
pub const VersionedRule = audit.VersionedRule;
pub const RuleFinding = audit.RuleFinding;
pub const EvaluationResult = audit.EvaluationResult;
pub const RuleInput = audit.RuleInput;
pub const RuleInputType = audit.RuleInputType;
pub const RuleRegistry = audit.RuleRegistry;
pub const RuleEngine = audit.RuleEngine;
pub const RuleEvaluationReport = audit.RuleEvaluationReport;
pub const BUILTIN_RULES = audit.BUILTIN_RULES;
pub const CVE_DISCLAIMER = audit.CVE_DISCLAIMER;

test "policy definitions compile" {
    const outcome = PolicyOutcome.pass;
    try testing.expectEqual(PolicyOutcome.pass, outcome);

    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();
    try testing.expect(reg.allRules().len >= 12);
}
