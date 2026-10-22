const std = @import("std");
const testing = std.testing;

pub const scope = @import("scope.zig");
pub const plan = @import("plan.zig");
pub const discovery = @import("discovery.zig");
pub const service = @import("service.zig");
pub const inventory = @import("inventory.zig");

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

pub const PortState = service.PortState;
pub const ConfidenceLevel = service.ConfidenceLevel;
pub const IdentificationMethod = service.IdentificationMethod;
pub const ServiceIdentity = service.ServiceIdentity;
pub const PortCheckResult = service.PortCheckResult;
pub const PortScanSummary = service.PortScanSummary;
pub const ServiceScanResult = service.ServiceScanResult;
pub const ServiceProber = service.ServiceProber;
pub const RealServiceProber = service.RealServiceProber;
pub const MockServiceProber = service.MockServiceProber;
pub const checkPortsAndIdentifyServices = service.checkPortsAndIdentifyServices;
pub const parseHttpHeadResponse = service.parseHttpHeadResponse;
pub const parseSshBanner = service.parseSshBanner;
pub const parseGreetingBanner = service.parseGreetingBanner;
pub const createUnrecognizedIdentity = service.createUnrecognizedIdentity;

pub const AssetService = inventory.AssetService;
pub const AssetHost = inventory.AssetHost;
pub const DiffCategory = inventory.DiffCategory;
pub const DiffEntry = inventory.DiffEntry;
pub const InventoryDiff = inventory.InventoryDiff;
pub const AssetInventory = inventory.AssetInventory;

test "recon root exports all submodules" {
    _ = scope;
    _ = plan;
    _ = discovery;
    _ = service;
    _ = inventory;
}
