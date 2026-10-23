const std = @import("std");
const testing = std.testing;

pub const synthetic = @import("synthetic.zig");
pub const scenario = @import("scenario.zig");
pub const service = @import("service.zig");
pub const manager = @import("manager.zig");
pub const verify = @import("verify.zig");
pub const exercises = @import("exercises.zig");

pub const LabScenarioId = scenario.LabScenarioId;
pub const LabScenario = scenario.LabScenario;
pub const ExpectedObservation = scenario.ExpectedObservation;
pub const LabLoopbackService = service.LabLoopbackService;
pub const ServiceKind = service.ServiceKind;
pub const LabManager = manager.LabManager;
pub const ActiveLabState = manager.ActiveLabState;
pub const VerificationResult = verify.VerificationResult;
pub const VerificationOutcome = verify.VerificationOutcome;
pub const ExerciseResult = exercises.ExerciseResult;
pub const runExercise = exercises.runExercise;

test "lab root module integration" {
    _ = synthetic;
    _ = scenario;
    _ = service;
    _ = manager;
    _ = verify;
    _ = exercises;
}
