const std = @import("std");
const testing = std.testing;

pub const scope = @import("scope.zig");
pub const plan = @import("plan.zig");
pub const discovery = @import("discovery.zig");

// Re-export core types and functions
pub const ScopeCaps = scope.ScopeCaps;
pub const ScopeError = scope.ScopeError;
pub const NormalizedScope = scope.NormalizedScope;
pub const normalizeScope = scope.normalizeScope;
pub const parsePortSpec = scope.parsePortSpec;
pub const expandCidr = scope.expandCidr;
pub const explainScopeError = scope.explainScopeError;
pub const isLoopbackTarget = scope.isLoopbackTarget;

pub const AssessmentPlanConfig = plan.AssessmentPlanConfig;
pub const AssessmentPlan = plan.AssessmentPlan;
pub const PlannedTask = plan.PlannedTask;
pub const CheckType = plan.CheckType;
pub const LEGAL_DISCLAIMER = plan.LEGAL_DISCLAIMER;
pub const DnsScopeError = plan.DnsScopeError;

pub const HostReachabilityState = discovery.HostReachabilityState;
pub const DiscoveryMethod = discovery.DiscoveryMethod;
pub const DiscoveryEvidence = discovery.DiscoveryEvidence;
pub const DiscoveredHost = discovery.DiscoveredHost;
pub const DiscoveryConfig = discovery.DiscoveryConfig;
pub const HostDiscoveryResult = discovery.HostDiscoveryResult;
pub const discoverHosts = discovery.discoverHosts;

test "recon root exports all submodules" {
    _ = scope;
    _ = plan;
    _ = discovery;
}
