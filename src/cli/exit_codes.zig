const std = @import("std");

/// Documented stable CLI exit codes (Master Specification Section 7.1)
pub const ExitCodes = struct {
    /// Successful execution without findings or policy violations
    pub const success: u8 = 0;
    /// Execution succeeded but security findings or policy violations were detected
    pub const findings_or_violations: u8 = 1;
    /// Invalid arguments, unknown command, malformed target, or out-of-scope input
    pub const invalid_input: u8 = 2;
    /// Operational failure (network unreachable, storage error, unexpected I/O)
    pub const operational_failure: u8 = 3;
    /// Assessment or operation cancelled by user signal or deadline
    pub const cancelled: u8 = 4;
};
