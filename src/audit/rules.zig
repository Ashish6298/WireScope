const std = @import("std");
const testing = std.testing;
const core = @import("../core/root.zig");

pub const Severity = core.models.Severity;
pub const Confidence = core.models.Confidence;

pub const CVE_DISCLAIMER: []const u8 =
    "WireScope evaluates defensive configuration and observable exposures only. " ++
    "WireScope makes no claim of comprehensive CVE vulnerability coverage, exploit verification, " ++
    "or proof-of-concept testing. Absence of findings does not indicate absence of application-layer vulnerabilities.";

pub const RuleCategory = enum {
    tls_configuration,
    http_configuration,
    listener_exposure,
    baseline_deviation,

    pub fn toSlice(self: RuleCategory) []const u8 {
        return @tagName(self);
    }
};

pub const RuleOutcome = enum {
    pass,
    fail,
    inconclusive,
    not_applicable,

    pub fn toSlice(self: RuleOutcome) []const u8 {
        return @tagName(self);
    }
};

pub const RuleValidationError = error{
    InvalidRuleId,
    InvalidRuleVersion,
    EmptyRuleTitle,
    EmptyRuleDescription,
    MissingRationale,
    MissingPreconditions,
    MissingRequiredEvidence,
    MissingLimitations,
    MissingRemediation,
};

pub const CookieObservation = struct {
    name: []const u8,
    is_secure: bool,
    is_http_only: bool,
    same_site: []const u8 = "",
};

pub const TlsObservation = struct {
    protocol_version: []const u8,
    hostname_matches: bool = true,
    is_valid_chain: bool = true,
    days_to_expiration: ?i32 = null,
    timed_out: bool = false,
    permission_denied: bool = false,
};

pub const HttpObservation = struct {
    is_https: bool = true,
    is_html: bool = true,
    is_json_api: bool = false,
    status_code: u16 = 200,
    hsts_header: ?[]const u8 = null,
    csp_header: ?[]const u8 = null,
    x_content_type_options: ?[]const u8 = null,
    x_frame_options: ?[]const u8 = null,
    cookies: []const CookieObservation = &.{},
    timed_out: bool = false,
};

pub const ListenerObservation = struct {
    address: []const u8,
    port: u16,
    transport: []const u8 = "tcp",
    binding_type: []const u8 = "wildcard",
    process_name: ?[]const u8 = null,
    expected_service: ?[]const u8 = null,
    expected_process: ?[]const u8 = null,
    is_unlisted: bool = false,
    permission_limited: bool = false,
};

pub const BaselineObservation = struct {
    item_id: []const u8,
    baseline_value: ?[]const u8 = null,
    current_value: ?[]const u8 = null,
    is_new: bool = false,
    is_removed: bool = false,
    is_modified: bool = false,
    evidence_incomplete: bool = false,
};

pub const RuleInputType = enum {
    tls_observation,
    http_observation,
    listener_observation,
    baseline_observation,
};

pub const RuleInput = union(RuleInputType) {
    tls_observation: TlsObservation,
    http_observation: HttpObservation,
    listener_observation: ListenerObservation,
    baseline_observation: BaselineObservation,
};

pub const RuleFinding = struct {
    rule_id: []const u8,
    rule_version: u32,
    title: []const u8,
    category: RuleCategory,
    severity: Severity,
    confidence: Confidence,
    severity_rationale: []const u8,
    evidence: []const u8,
    context_evaluation: []const u8,
    remediation: []const u8,
    limitations: []const u8,
    cve_disclaimer: []const u8 = CVE_DISCLAIMER,
};

pub const EvaluationResult = struct {
    outcome: RuleOutcome,
    finding: ?RuleFinding = null,
    explanation: []const u8,
};

pub const VersionedRule = struct {
    id: []const u8,
    version: u32,
    title: []const u8,
    description: []const u8,
    category: RuleCategory,
    severity: Severity,
    confidence: Confidence,
    rationale: []const u8,
    preconditions: []const u8,
    required_evidence: []const u8,
    limitations: []const u8,
    remediation: []const u8,
    evaluator: *const fn (rule: *const VersionedRule, input: *const RuleInput) EvaluationResult,

    pub fn validate(self: VersionedRule) RuleValidationError!void {
        if (self.id.len == 0 or self.id.len > 128 or !std.mem.startsWith(u8, self.id, "WS-RULE-")) {
            return error.InvalidRuleId;
        }
        if (self.version == 0) {
            return error.InvalidRuleVersion;
        }
        if (self.title.len == 0) {
            return error.EmptyRuleTitle;
        }
        if (self.description.len == 0) {
            return error.EmptyRuleDescription;
        }
        if (self.rationale.len == 0) {
            return error.MissingRationale;
        }
        if (self.preconditions.len == 0) {
            return error.MissingPreconditions;
        }
        if (self.required_evidence.len == 0) {
            return error.MissingRequiredEvidence;
        }
        if (self.limitations.len == 0) {
            return error.MissingLimitations;
        }
        if (self.remediation.len == 0) {
            return error.MissingRemediation;
        }
    }
};

// -----------------------------------------------------------------------------
// Evaluator Implementations
// -----------------------------------------------------------------------------

fn evalTlsMinVersion(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .tls_observation => |obs| {
            if (obs.timed_out or obs.permission_denied) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "TLS probe timed out or permission was denied before protocol handshake completed.",
                };
            }
            if (obs.protocol_version.len == 0) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Target protocol version string missing from observation.",
                };
            }
            if (std.mem.eql(u8, obs.protocol_version, "TLSv1.3") or std.mem.eql(u8, obs.protocol_version, "TLSv1.2")) {
                return .{
                    .outcome = .pass,
                    .explanation = "Modern TLS protocol version negotiated (TLS 1.2+).",
                };
            }
            return .{
                .outcome = .fail,
                .explanation = "Target negotiated deprecated TLS version.",
                .finding = .{
                    .rule_id = rule.id,
                    .rule_version = rule.version,
                    .title = rule.title,
                    .category = rule.category,
                    .severity = rule.severity,
                    .confidence = rule.confidence,
                    .severity_rationale = rule.rationale,
                    .evidence = obs.protocol_version,
                    .context_evaluation = "Negotiated TLS protocol version is below the defensive baseline of TLS 1.2.",
                    .remediation = rule.remediation,
                    .limitations = rule.limitations,
                },
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a TLS observation.",
        },
    }
}

fn evalTlsCertExpiration(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .tls_observation => |obs| {
            if (obs.timed_out or obs.permission_denied) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Certificate observation incomplete due to timeout or permission denial.",
                };
            }
            if (obs.days_to_expiration) |days| {
                if (days <= 0) {
                    return .{
                        .outcome = .fail,
                        .explanation = "Certificate is already expired.",
                        .finding = .{
                            .rule_id = rule.id,
                            .rule_version = rule.version,
                            .title = rule.title,
                            .category = rule.category,
                            .severity = .high,
                            .confidence = rule.confidence,
                            .severity_rationale = "Expired TLS certificates cause trust validation failures and client rejection.",
                            .evidence = "Certificate expired (<= 0 days remaining).",
                            .context_evaluation = "Certificate validity period has lapsed.",
                            .remediation = rule.remediation,
                            .limitations = rule.limitations,
                        },
                    };
                } else if (days <= 14) {
                    return .{
                        .outcome = .fail,
                        .explanation = "Certificate will expire in under 14 days.",
                        .finding = .{
                            .rule_id = rule.id,
                            .rule_version = rule.version,
                            .title = rule.title,
                            .category = rule.category,
                            .severity = rule.severity,
                            .confidence = rule.confidence,
                            .severity_rationale = rule.rationale,
                            .evidence = "Certificate expiration is imminent (<= 14 days).",
                            .context_evaluation = "Certificate replacement required before expiration window closes.",
                            .remediation = rule.remediation,
                            .limitations = rule.limitations,
                        },
                    };
                }
                return .{
                    .outcome = .pass,
                    .explanation = "Certificate validity window is sufficient (> 14 days remaining).",
                };
            }
            return .{
                .outcome = .inconclusive,
                .explanation = "Certificate expiration date was not observed.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a TLS observation.",
        },
    }
}

fn evalTlsHostnameMatch(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .tls_observation => |obs| {
            if (obs.timed_out or obs.permission_denied) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Hostname validation observation could not complete.",
                };
            }
            if (obs.hostname_matches) {
                return .{
                    .outcome = .pass,
                    .explanation = "Subject Alternative Name (SAN) or Common Name (CN) matches target host.",
                };
            }
            return .{
                .outcome = .fail,
                .explanation = "Certificate identity does not match the requested hostname.",
                .finding = .{
                    .rule_id = rule.id,
                    .rule_version = rule.version,
                    .title = rule.title,
                    .category = rule.category,
                    .severity = rule.severity,
                    .confidence = rule.confidence,
                    .severity_rationale = rule.rationale,
                    .evidence = "Target host not listed in Certificate SAN/CN attributes.",
                    .context_evaluation = "Mismatched certificates fail TLS trust and permit man-in-the-middle attacks.",
                    .remediation = rule.remediation,
                    .limitations = rule.limitations,
                },
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a TLS observation.",
        },
    }
}

fn evalHttpHsts(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .http_observation => |obs| {
            if (obs.timed_out) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "HTTP request timed out before response headers were received.",
                };
            }
            if (!obs.is_https) {
                return .{
                    .outcome = .not_applicable,
                    .explanation = "RFC 6797 prohibits HSTS over unencrypted plain HTTP transport.",
                };
            }
            if (obs.hsts_header) |hdr| {
                if (std.mem.indexOf(u8, hdr, "max-age=") != null) {
                    return .{
                        .outcome = .pass,
                        .explanation = "Valid Strict-Transport-Security header detected over HTTPS.",
                    };
                }
            }
            return .{
                .outcome = .fail,
                .explanation = "Missing or malformed Strict-Transport-Security header on HTTPS endpoint.",
                .finding = .{
                    .rule_id = rule.id,
                    .rule_version = rule.version,
                    .title = rule.title,
                    .category = rule.category,
                    .severity = rule.severity,
                    .confidence = rule.confidence,
                    .severity_rationale = rule.rationale,
                    .evidence = if (obs.hsts_header) |h| h else "Header absent in HTTPS response",
                    .context_evaluation = "Without HSTS, clients may be downgraded to unencrypted HTTP by adjacent network attackers.",
                    .remediation = rule.remediation,
                    .limitations = rule.limitations,
                },
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not an HTTP observation.",
        },
    }
}

fn evalHttpCsp(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .http_observation => |obs| {
            if (obs.timed_out) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "HTTP response timed out before headers arrived.",
                };
            }
            if (obs.is_json_api or !obs.is_html) {
                return .{
                    .outcome = .not_applicable,
                    .explanation = "Non-HTML documents (e.g. JSON API endpoints) do not parse or execute HTML scripts; CSP is inapplicable.",
                };
            }
            if (obs.csp_header) |csp| {
                if (std.mem.indexOf(u8, csp, "'unsafe-inline'") != null or std.mem.indexOf(u8, csp, "'unsafe-eval'") != null) {
                    return .{
                        .outcome = .fail,
                        .explanation = "CSP contains unsafe-inline or unsafe-eval keywords.",
                        .finding = .{
                            .rule_id = rule.id,
                            .rule_version = rule.version,
                            .title = rule.title,
                            .category = rule.category,
                            .severity = rule.severity,
                            .confidence = rule.confidence,
                            .severity_rationale = rule.rationale,
                            .evidence = csp,
                            .context_evaluation = "CSP permits inline script execution or dynamic eval, diminishing defense-in-depth against XSS.",
                            .remediation = rule.remediation,
                            .limitations = rule.limitations,
                        },
                    };
                }
                return .{
                    .outcome = .pass,
                    .explanation = "Strict Content-Security-Policy header detected on HTML document.",
                };
            }
            return .{
                .outcome = .fail,
                .explanation = "Missing Content-Security-Policy header on HTML document.",
                .finding = .{
                    .rule_id = rule.id,
                    .rule_version = rule.version,
                    .title = rule.title,
                    .category = rule.category,
                    .severity = rule.severity,
                    .confidence = rule.confidence,
                    .severity_rationale = rule.rationale,
                    .evidence = "Content-Security-Policy header absent",
                    .context_evaluation = "Absence of CSP reduces defense-in-depth against cross-site scripting vulnerabilities.",
                    .remediation = rule.remediation,
                    .limitations = rule.limitations,
                },
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not an HTTP observation.",
        },
    }
}

fn evalHttpNosniff(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .http_observation => |obs| {
            if (obs.timed_out) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "HTTP response timed out before headers arrived.",
                };
            }
            if (obs.x_content_type_options) |val| {
                if (std.ascii.eqlIgnoreCase(val, "nosniff")) {
                    return .{
                        .outcome = .pass,
                        .explanation = "X-Content-Type-Options: nosniff header detected.",
                    };
                }
            }
            return .{
                .outcome = .fail,
                .explanation = "Missing or invalid X-Content-Type-Options header.",
                .finding = .{
                    .rule_id = rule.id,
                    .rule_version = rule.version,
                    .title = rule.title,
                    .category = rule.category,
                    .severity = rule.severity,
                    .confidence = rule.confidence,
                    .severity_rationale = rule.rationale,
                    .evidence = if (obs.x_content_type_options) |v| v else "Header absent",
                    .context_evaluation = "Missing nosniff header allows MIME sniffing of text/plain as executable script.",
                    .remediation = rule.remediation,
                    .limitations = rule.limitations,
                },
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not an HTTP observation.",
        },
    }
}

fn evalHttpCookieFlags(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .http_observation => |obs| {
            if (obs.timed_out) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "HTTP response timed out.",
                };
            }
            if (obs.cookies.len == 0) {
                return .{
                    .outcome = .pass,
                    .explanation = "No cookies set in HTTP response; cookie security requirements satisfied.",
                };
            }
            for (obs.cookies) |c| {
                if (obs.is_https and !c.is_secure) {
                    return .{
                        .outcome = .fail,
                        .explanation = "Cookie missing Secure flag on HTTPS response.",
                        .finding = .{
                            .rule_id = rule.id,
                            .rule_version = rule.version,
                            .title = rule.title,
                            .category = rule.category,
                            .severity = rule.severity,
                            .confidence = rule.confidence,
                            .severity_rationale = rule.rationale,
                            .evidence = c.name,
                            .context_evaluation = "Insecure cookie transmitted over HTTPS can be leaked if client later visits HTTP variant.",
                            .remediation = rule.remediation,
                            .limitations = rule.limitations,
                        },
                    };
                }
                if (!c.is_http_only) {
                    return .{
                        .outcome = .fail,
                        .explanation = "Cookie missing HttpOnly attribute.",
                        .finding = .{
                            .rule_id = rule.id,
                            .rule_version = rule.version,
                            .title = rule.title,
                            .category = rule.category,
                            .severity = .low,
                            .confidence = rule.confidence,
                            .severity_rationale = "Cookies lacking HttpOnly can be accessed via document.cookie if XSS occurs.",
                            .evidence = c.name,
                            .context_evaluation = "Session or authentication cookie exposed to JavaScript DOM.",
                            .remediation = rule.remediation,
                            .limitations = rule.limitations,
                        },
                    };
                }
            }
            return .{
                .outcome = .pass,
                .explanation = "All observed cookies include Secure and HttpOnly flags.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not an HTTP observation.",
        },
    }
}

fn evalExposureWildcard(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .listener_observation => |obs| {
            if (obs.permission_limited) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Socket table inspection permission limited; wildcard binding cannot be reliably audited.",
                };
            }
            if (std.mem.eql(u8, obs.binding_type, "wildcard") or std.mem.eql(u8, obs.address, "0.0.0.0") or std.mem.eql(u8, obs.address, "::")) {
                return .{
                    .outcome = .fail,
                    .explanation = "Socket is bound to a wildcard network address (0.0.0.0 or ::).",
                    .finding = .{
                        .rule_id = rule.id,
                        .rule_version = rule.version,
                        .title = rule.title,
                        .category = rule.category,
                        .severity = rule.severity,
                        .confidence = rule.confidence,
                        .severity_rationale = rule.rationale,
                        .evidence = obs.address,
                        .context_evaluation = "Wildcard socket binding exposes service on all network interfaces including public and untrusted links.",
                        .remediation = rule.remediation,
                        .limitations = rule.limitations,
                    },
                };
            }
            return .{
                .outcome = .pass,
                .explanation = "Socket is bound to a restricted loopback or specific interface address.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a listener observation.",
        },
    }
}

fn evalExposureUnexpected(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .listener_observation => |obs| {
            if (obs.permission_limited) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Process/listener inspection restricted by host permissions; cannot verify listener approval.",
                };
            }
            if (obs.is_unlisted) {
                return .{
                    .outcome = .fail,
                    .explanation = "Observed listener is not present in approved policy.",
                    .finding = .{
                        .rule_id = rule.id,
                        .rule_version = rule.version,
                        .title = rule.title,
                        .category = rule.category,
                        .severity = rule.severity,
                        .confidence = rule.confidence,
                        .severity_rationale = rule.rationale,
                        .evidence = obs.address,
                        .context_evaluation = "Undocumented listening socket increases attack surface and indicates unmanaged software.",
                        .remediation = rule.remediation,
                        .limitations = rule.limitations,
                    },
                };
            }
            return .{
                .outcome = .pass,
                .explanation = "Listener matches approved service policy baseline.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a listener observation.",
        },
    }
}

fn evalExposurePermission(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .listener_observation => |obs| {
            if (obs.permission_limited) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Listener inspection encountered permission restrictions. WireScope cannot assert zero exposure.",
                    .finding = .{
                        .rule_id = rule.id,
                        .rule_version = rule.version,
                        .title = rule.title,
                        .category = rule.category,
                        .severity = rule.severity,
                        .confidence = rule.confidence,
                        .severity_rationale = rule.rationale,
                        .evidence = "Unprivileged user execution; socket table process names partially obscured.",
                        .context_evaluation = "Audit results reflect partial visibility. Elevated privileges required for complete audit.",
                        .remediation = rule.remediation,
                        .limitations = rule.limitations,
                    },
                };
            }
            return .{
                .outcome = .pass,
                .explanation = "Full platform permissions available; complete listener table inspected.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a listener observation.",
        },
    }
}

fn evalBaselineUnexpected(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .baseline_observation => |obs| {
            if (obs.evidence_incomplete) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Baseline comparison observation was incomplete or interrupted.",
                };
            }
            if (obs.is_new) {
                return .{
                    .outcome = .fail,
                    .explanation = "Observed service was not present in the baseline snapshot.",
                    .finding = .{
                        .rule_id = rule.id,
                        .rule_version = rule.version,
                        .title = rule.title,
                        .category = rule.category,
                        .severity = rule.severity,
                        .confidence = rule.confidence,
                        .severity_rationale = rule.rationale,
                        .evidence = obs.item_id,
                        .context_evaluation = "An unexpected service or port appeared since the approved baseline snapshot.",
                        .remediation = rule.remediation,
                        .limitations = rule.limitations,
                    },
                };
            }
            return .{
                .outcome = .pass,
                .explanation = "Observed item conforms to baseline inventory.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a baseline observation.",
        },
    }
}

fn evalBaselineRemoved(rule: *const VersionedRule, input: *const RuleInput) EvaluationResult {
    switch (input.*) {
        .baseline_observation => |obs| {
            if (obs.evidence_incomplete) {
                return .{
                    .outcome = .inconclusive,
                    .explanation = "Observation incomplete; lack of response must not be treated as service removal.",
                };
            }
            if (obs.is_removed) {
                return .{
                    .outcome = .fail,
                    .explanation = "Service present in approved baseline is no longer listening.",
                    .finding = .{
                        .rule_id = rule.id,
                        .rule_version = rule.version,
                        .title = rule.title,
                        .category = rule.category,
                        .severity = rule.severity,
                        .confidence = rule.confidence,
                        .severity_rationale = rule.rationale,
                        .evidence = obs.item_id,
                        .context_evaluation = "Expected baseline service is offline or stopped.",
                        .remediation = rule.remediation,
                        .limitations = rule.limitations,
                    },
                };
            }
            return .{
                .outcome = .pass,
                .explanation = "Baseline service confirmed active.",
            };
        },
        else => return .{
            .outcome = .not_applicable,
            .explanation = "Input is not a baseline observation.",
        },
    }
}

// -----------------------------------------------------------------------------
// Built-in Versioned Rules Catalog
// -----------------------------------------------------------------------------

pub const BUILTIN_RULES = [_]VersionedRule{
    // Category 1: TLS Configuration
    .{
        .id = "WS-RULE-TLS-MIN-VERSION",
        .version = 1,
        .title = "Enforce Modern TLS Protocol Version (TLS 1.2+)",
        .description = "Inspects negotiated TLS version and rejects legacy protocol versions (TLS 1.0, 1.1, SSLv3).",
        .category = .tls_configuration,
        .severity = .high,
        .confidence = .confirmed,
        .rationale = "Legacy TLS protocols suffer from known cryptographic design flaws and lack modern authenticated encryption suites.",
        .preconditions = "Endpoint must support TLS handshake; network path must be reachable.",
        .required_evidence = "Negotiated TLS protocol version string.",
        .limitations = "Assesses the protocol version negotiated by the client probe; server may support other versions with different cipher configurations.",
        .remediation = "Disable TLS 1.0, TLS 1.1, and SSLv3 in server configuration; enable TLS 1.2 and TLS 1.3.",
        .evaluator = evalTlsMinVersion,
    },
    .{
        .id = "WS-RULE-TLS-CERT-EXPIRATION",
        .version = 1,
        .title = "Detect Expired or Expiring X.509 Certificate",
        .description = "Verifies certificate validity period and warns when certificate has expired or expiration is imminent.",
        .category = .tls_configuration,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "Expired TLS certificates cause trust failures, operational disruption, and user warnings.",
        .preconditions = "Target must present an X.509 certificate during TLS handshake.",
        .required_evidence = "Certificate notAfter expiration timestamp.",
        .limitations = "Calculated relative to local system clock; requires synchronized host time.",
        .remediation = "Renew and deploy an updated certificate before current validity window expires.",
        .evaluator = evalTlsCertExpiration,
    },
    .{
        .id = "WS-RULE-TLS-HOSTNAME-MATCH",
        .version = 1,
        .title = "Enforce TLS Hostname Identity Verification",
        .description = "Verifies that the requested target hostname matches Subject Alternative Name (SAN) or CN.",
        .category = .tls_configuration,
        .severity = .high,
        .confidence = .confirmed,
        .rationale = "Hostname verification prevents man-in-the-middle attacks using valid certificates issued for other domains.",
        .preconditions = "TLS handshake succeeds and target certificate is presented.",
        .required_evidence = "Certificate Subject Alternative Name (SAN) list and target hostname.",
        .limitations = "Evaluates against the supplied target hostname or IP address.",
        .remediation = "Configure server to present a certificate matching the target domain or add domain to SAN.",
        .evaluator = evalTlsHostnameMatch,
    },

    // Category 2: HTTP Configuration
    .{
        .id = "WS-RULE-HTTP-HSTS-POLICY",
        .version = 1,
        .title = "Require HTTP Strict Transport Security (HSTS) on HTTPS",
        .description = "Verifies presence of Strict-Transport-Security header with sufficient max-age on HTTPS endpoints.",
        .category = .http_configuration,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "HSTS prevents SSL stripping and unencrypted downgrade attacks by forcing browsers to connect via HTTPS.",
        .preconditions = "Target must be accessible over HTTPS.",
        .required_evidence = "Strict-Transport-Security response header value.",
        .limitations = "Cannot verify browser preload list inclusion or subdomain policy coverage without recursive auditing.",
        .remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to HTTPS response headers.",
        .evaluator = evalHttpHsts,
    },
    .{
        .id = "WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION",
        .version = 1,
        .title = "Restrict Insecure Script Execution via Content Security Policy",
        .description = "Ensures HTML endpoints declare a Content-Security-Policy header without unsafe-inline or unsafe-eval.",
        .category = .http_configuration,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "Content-Security-Policy mitigates Cross-Site Scripting (XSS) by restricting sources of executable script.",
        .preconditions = "Target response must have an HTML content-type.",
        .required_evidence = "Content-Security-Policy response header directives.",
        .limitations = "Inapplicable to JSON APIs and non-HTML assets; does not parse complex dynamic nonce behaviors.",
        .remediation = "Define a CSP header restricting script-src to trusted sources; avoid 'unsafe-inline' and 'unsafe-eval'.",
        .evaluator = evalHttpCsp,
    },
    .{
        .id = "WS-RULE-HTTP-NOSNIFF-HEADER",
        .version = 1,
        .title = "Enforce MIME-Type Sniffing Protection (X-Content-Type-Options)",
        .description = "Verifies that responses include X-Content-Type-Options: nosniff.",
        .category = .http_configuration,
        .severity = .low,
        .confidence = .confirmed,
        .rationale = "Prevents browsers from MIME-sniffing a response into an executable content type.",
        .preconditions = "HTTP response received from target.",
        .required_evidence = "X-Content-Type-Options response header.",
        .limitations = "Defensive header check; does not test browser interpretation of ambiguous MIME types.",
        .remediation = "Configure web server to return 'X-Content-Type-Options: nosniff'.",
        .evaluator = evalHttpNosniff,
    },
    .{
        .id = "WS-RULE-HTTP-COOKIE-FLAGS",
        .version = 1,
        .title = "Enforce Secure and HttpOnly Cookie Security Attributes",
        .description = "Verifies that session cookies sent over HTTPS include Secure and HttpOnly attributes.",
        .category = .http_configuration,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "Cookies lacking Secure can be transmitted over cleartext HTTP; lacking HttpOnly permits XSS cookie theft.",
        .preconditions = "HTTP response contains Set-Cookie headers.",
        .required_evidence = "Set-Cookie attributes in response.",
        .limitations = "Cannot discern business criticality of individual cookie tokens; flags all unhardened cookies on HTTPS.",
        .remediation = "Append '; Secure; HttpOnly; SameSite=Lax' to sensitive Set-Cookie headers.",
        .evaluator = evalHttpCookieFlags,
    },

    // Category 3: Listener Exposure
    .{
        .id = "WS-RULE-EXPOSURE-WILDCARD-BINDING",
        .version = 1,
        .title = "Audit Unapproved Wildcard Socket Bindings",
        .description = "Identifies local listening sockets bound to wildcard addresses (0.0.0.0 or ::).",
        .category = .listener_exposure,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "Wildcard bindings expose services across all network interfaces, including public and untrusted networks.",
        .preconditions = "Host socket table inspection permitted by operating system.",
        .required_evidence = "Socket local address and port binding.",
        .limitations = "Does not inspect host firewall rules (Windows Filtering Platform / iptables); purely checks socket binding.",
        .remediation = "Bind services exclusively to 127.0.0.1/::1 or specific approved network interfaces.",
        .evaluator = evalExposureWildcard,
    },
    .{
        .id = "WS-RULE-EXPOSURE-UNEXPECTED-LISTENER",
        .version = 1,
        .title = "Detect Undocumented Listening Services",
        .description = "Identifies listening sockets not accounted for in approved service policy.",
        .category = .listener_exposure,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "Undocumented listeners expand attack surface and indicate configuration drift or shadow IT.",
        .preconditions = "Expected service policy defined and socket inventory available.",
        .required_evidence = "Listening port and transport protocol.",
        .limitations = "Relies on accuracy of user-provided expected services policy.",
        .remediation = "Document approved services in policy or terminate unauthorized listening daemon.",
        .evaluator = evalExposureUnexpected,
    },
    .{
        .id = "WS-RULE-EXPOSURE-PERMISSION-BOUNDARY",
        .version = 1,
        .title = "Verify Administrative Visibility into Local Listening Sockets",
        .description = "Checks whether socket inspection was limited by unprivileged user permissions.",
        .category = .listener_exposure,
        .severity = .info,
        .confidence = .confirmed,
        .rationale = "When executed without elevated privileges, some daemon names and PIDs are obscured.",
        .preconditions = "Platform listener enumeration invoked.",
        .required_evidence = "Platform permission status indicator.",
        .limitations = "Informational boundary indicator; does not alter system privileges.",
        .remediation = "Execute WireScope with administrator or root privileges for full process identification.",
        .evaluator = evalExposurePermission,
    },

    // Category 4: Baseline Deviation
    .{
        .id = "WS-RULE-BASELINE-UNEXPECTED-SERVICE",
        .version = 1,
        .title = "Detect New Services Absent from Approved Baseline",
        .description = "Flags new listening services or open ports detected relative to a previous baseline snapshot.",
        .category = .baseline_deviation,
        .severity = .medium,
        .confidence = .confirmed,
        .rationale = "New services appearing without baseline update represent unexpected configuration drift.",
        .preconditions = "A valid baseline snapshot must exist for comparison.",
        .required_evidence = "Baseline item ID and current observation status.",
        .limitations = "Subject to timing differences; ephemeral ports may trigger false positives if not filtered.",
        .remediation = "Review the newly discovered service and either update baseline or decommission service.",
        .evaluator = evalBaselineUnexpected,
    },
    .{
        .id = "WS-RULE-BASELINE-SERVICE-REMOVED",
        .version = 1,
        .title = "Detect Missing Services Present in Approved Baseline",
        .description = "Flags expected baseline services that are no longer actively listening.",
        .category = .baseline_deviation,
        .severity = .low,
        .confidence = .confirmed,
        .rationale = "Unexpected removal of baseline services indicates service failure or unscheduled downtime.",
        .preconditions = "A valid baseline snapshot must exist for comparison.",
        .required_evidence = "Baseline item ID and absence confirmation.",
        .limitations = "Network timeouts must not be classified as service removal (inconclusive outcome used).",
        .remediation = "Restart missing service or update baseline snapshot if service was decommissioned.",
        .evaluator = evalBaselineRemoved,
    },
};

// -----------------------------------------------------------------------------
// Rule Registry
// -----------------------------------------------------------------------------

pub const RuleRegistry = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayListUnmanaged(VersionedRule),

    pub fn init(allocator: std.mem.Allocator) RuleRegistry {
        return .{
            .allocator = allocator,
            .rules = std.ArrayListUnmanaged(VersionedRule){},
        };
    }

    pub fn deinit(self: *RuleRegistry) void {
        self.rules.deinit(self.allocator);
    }

    pub fn register(self: *RuleRegistry, rule: VersionedRule) RuleValidationError!void {
        try rule.validate();
        // Check for duplicates
        for (self.rules.items) |existing| {
            if (std.mem.eql(u8, existing.id, rule.id)) {
                return; // already registered
            }
        }
        self.rules.append(self.allocator, rule) catch return;
    }

    pub fn registerDefaults(self: *RuleRegistry) void {
        for (BUILTIN_RULES) |rule| {
            self.register(rule) catch {};
        }
    }

    pub fn getRule(self: *const RuleRegistry, id: []const u8) ?*const VersionedRule {
        for (self.rules.items) |*rule| {
            if (std.mem.eql(u8, rule.id, id)) {
                return rule;
            }
        }
        return null;
    }

    pub fn allRules(self: *const RuleRegistry) []const VersionedRule {
        return self.rules.items;
    }

    pub fn toTerminal(self: *const RuleRegistry, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE VERSIONED DEFENSIVE RULES REGISTRY
            \\================================================================================
            \\Total Registered Rules: {d}
            \\
            \\  Rule ID                            Ver  Category             Severity  Title
            \\  --------------------------------------------------------------------------------
            \\
        , .{self.rules.items.len});

        for (self.rules.items) |rule| {
            try writer.print("  {s:<34} v{d:<3} {s:<20} {s:<9} {s}\n", .{
                rule.id,
                rule.version,
                rule.category.toSlice(),
                rule.severity.toSlice(),
                rule.title,
            });
        }

        try writer.print(
            \\================================================================================
            \\WireScope CVE Disclaimer:
            \\  {s}
            \\================================================================================
            \\
        , .{CVE_DISCLAIMER});
    }

    pub fn toJson(self: *const RuleRegistry, writer: anytype) !void {
        try writer.print(
            \\{{"registry_type":"versioned_rules","schema_version":1,"total_rules":{d},"cve_disclaimer":"{s}","rules":[
        , .{ self.rules.items.len, CVE_DISCLAIMER });

        for (self.rules.items, 0..) |rule, i| {
            if (i > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"id":"{s}","version":{d},"title":"{s}","category":"{s}","severity":"{s}","confidence":"{s}","rationale":"{s}","preconditions":"{s}","limitations":"{s}","remediation":"{s}"}}
            , .{
                rule.id,
                rule.version,
                rule.title,
                rule.category.toSlice(),
                rule.severity.toSlice(),
                rule.confidence.toSlice(),
                rule.rationale,
                rule.preconditions,
                rule.limitations,
                rule.remediation,
            });
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const RuleRegistry, writer: anytype) !void {
        try writer.print(
            \\# WireScope Versioned Defensive Rules Registry
            \\
            \\**Total Registered Rules:** {d}  
            \\
            \\> [!NOTE]
            \\> {s}
            \\
            \\| Rule ID | Version | Category | Severity | Confidence | Title |
            \\| :--- | :---: | :--- | :--- | :--- | :--- |
            \\
        , .{ self.rules.items.len, CVE_DISCLAIMER });

        for (self.rules.items) |rule| {
            try writer.print("| `{s}` | `{d}` | `{s}` | `{s}` | `{s}` | {s} |\n", .{
                rule.id,
                rule.version,
                rule.category.toSlice(),
                rule.severity.toSlice(),
                rule.confidence.toSlice(),
                rule.title,
            });
        }
    }
};

// -----------------------------------------------------------------------------
// Rule Evaluation Engine & Report
// -----------------------------------------------------------------------------

pub const RuleEvaluationReport = struct {
    total_evaluated: usize = 0,
    passed_count: usize = 0,
    failed_count: usize = 0,
    inconclusive_count: usize = 0,
    not_applicable_count: usize = 0,
    findings: std.ArrayListUnmanaged(RuleFinding),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RuleEvaluationReport {
        return .{
            .findings = std.ArrayListUnmanaged(RuleFinding){},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RuleEvaluationReport) void {
        self.findings.deinit(self.allocator);
    }

    pub fn record(self: *RuleEvaluationReport, result: EvaluationResult) !void {
        self.total_evaluated += 1;
        switch (result.outcome) {
            .pass => self.passed_count += 1,
            .fail => {
                self.failed_count += 1;
                if (result.finding) |f| {
                    try self.findings.append(self.allocator, f);
                }
            },
            .inconclusive => {
                self.inconclusive_count += 1;
                if (result.finding) |f| {
                    try self.findings.append(self.allocator, f);
                }
            },
            .not_applicable => self.not_applicable_count += 1,
        }
    }

    pub fn toTerminal(self: *const RuleEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\================================================================================
            \\WIRESCOPE DEFENSIVE RULE EVALUATION REPORT
            \\================================================================================
            \\Summary Metrics:
            \\  Total Checks Evaluated: {d}
            \\  Passed (Compliant):      {d}
            \\  Failed (Violations):     {d}
            \\  Inconclusive:            {d}
            \\  Not Applicable:          {d}
            \\
        , .{
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
        });

        if (self.findings.items.len > 0) {
            try writer.print("--- EVALUATION FINDINGS ---\n\n", .{});
            for (self.findings.items, 1..) |f, i| {
                try writer.print(
                    \\[{d}] [{s}] {s} ({s} v{d})
                    \\    Category:           {s}
                    \\    Confidence:         {s}
                    \\    Severity Rationale: {s}
                    \\    Evidence:           {s}
                    \\    Context:            {s}
                    \\    Remediation:        {s}
                    \\    Limitations:        {s}
                    \\
                    \\
                , .{
                    i,
                    f.severity.toSlice(),
                    f.title,
                    f.rule_id,
                    f.rule_version,
                    f.category.toSlice(),
                    f.confidence.toSlice(),
                    f.severity_rationale,
                    f.evidence,
                    f.context_evaluation,
                    f.remediation,
                    f.limitations,
                });
            }
        } else {
            try writer.print("All evaluated rules conformed to defensive policy standards.\n\n", .{});
        }

        try writer.print(
            \\================================================================================
            \\WireScope CVE Disclaimer:
            \\  {s}
            \\================================================================================
            \\
        , .{CVE_DISCLAIMER});
    }

    pub fn toJson(self: *const RuleEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\{{"report_type":"rule_evaluation","schema_version":1,"metrics":{{"total":{d},"passed":{d},"failed":{d},"inconclusive":{d},"not_applicable":{d}}},"cve_disclaimer":"{s}","findings":[
        , .{
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
            CVE_DISCLAIMER,
        });

        for (self.findings.items, 0..) |f, i| {
            if (i > 0) try writer.print(",", .{});
            try writer.print(
                \\{{"rule_id":"{s}","rule_version":{d},"title":"{s}","category":"{s}","severity":"{s}","confidence":"{s}","evidence":"{s}","limitations":"{s}","remediation":"{s}"}}
            , .{
                f.rule_id,
                f.rule_version,
                f.title,
                f.category.toSlice(),
                f.severity.toSlice(),
                f.confidence.toSlice(),
                f.evidence,
                f.limitations,
                f.remediation,
            });
        }

        try writer.print("]}}\n", .{});
    }

    pub fn toMarkdown(self: *const RuleEvaluationReport, writer: anytype) !void {
        try writer.print(
            \\# WireScope Defensive Rule Evaluation Report
            \\
            \\**Total Evaluated:** {d} | **Passed:** {d} | **Failed:** {d} | **Inconclusive:** {d} | **Not Applicable:** {d}  
            \\
            \\> [!NOTE]
            \\> {s}
            \\
        , .{
            self.total_evaluated,
            self.passed_count,
            self.failed_count,
            self.inconclusive_count,
            self.not_applicable_count,
            CVE_DISCLAIMER,
        });

        if (self.findings.items.len > 0) {
            try writer.print("\n## Defensive Findings\n\n", .{});
            for (self.findings.items) |f| {
                try writer.print(
                    \\### {s} — {s}
                    \\
                    \\- **Rule ID:** `{s}` (v{d})
                    \\- **Category:** `{s}`
                    \\- **Severity:** `{s}` | **Confidence:** `{s}`
                    \\- **Severity Rationale:** {s}
                    \\- **Evidence:** `{s}`
                    \\- **Context Evaluation:** {s}
                    \\- **Remediation:** {s}
                    \\- **Limitations:** {s}
                    \\
                    \\
                , .{
                    f.rule_id,
                    f.title,
                    f.rule_id,
                    f.rule_version,
                    f.category.toSlice(),
                    f.severity.toSlice(),
                    f.confidence.toSlice(),
                    f.severity_rationale,
                    f.evidence,
                    f.context_evaluation,
                    f.remediation,
                    f.limitations,
                });
            }
        }
    }
};

pub const RuleEngine = struct {
    registry: *const RuleRegistry,

    pub fn init(registry: *const RuleRegistry) RuleEngine {
        return .{
            .registry = registry,
        };
    }

    pub fn evaluateSingle(self: *const RuleEngine, rule_id: []const u8, input: *const RuleInput) ?EvaluationResult {
        const rule = self.registry.getRule(rule_id) orelse return null;
        return rule.evaluator(rule, input);
    }

    pub fn evaluateAll(self: *const RuleEngine, allocator: std.mem.Allocator, inputs: []const RuleInput) !RuleEvaluationReport {
        var report = RuleEvaluationReport.init(allocator);
        for (self.registry.allRules()) |*rule| {
            for (inputs) |*input| {
                const res = rule.evaluator(rule, input);
                try report.record(res);
            }
        }
        return report;
    }
};

// -----------------------------------------------------------------------------
// Unit & Integration Tests (Covering Positive, Negative, Inconclusive, Malformed)
// -----------------------------------------------------------------------------

test "rules engine: rules have stable IDs and versions" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();

    try testing.expectEqual(@as(usize, 12), reg.rules.items.len);

    for (reg.rules.items) |rule| {
        try testing.expect(std.mem.startsWith(u8, rule.id, "WS-RULE-"));
        try testing.expect(rule.version >= 1);
        try testing.expect(rule.title.len > 0);
        try testing.expect(rule.rationale.len > 0);
        try testing.expect(rule.limitations.len > 0);
        try testing.expect(rule.remediation.len > 0);
    }

    const tls_rule = reg.getRule("WS-RULE-TLS-MIN-VERSION");
    try testing.expect(tls_rule != null);
    try testing.expectEqual(@as(u32, 1), tls_rule.?.version);
    try testing.expectEqual(RuleCategory.tls_configuration, tls_rule.?.category);
    try testing.expectEqual(Severity.high, tls_rule.?.severity);
    try testing.expectEqual(Confidence.confirmed, tls_rule.?.confidence);
}

test "rules engine: positive, negative, inconclusive, and not-applicable cases for TLS min version" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();
    const engine = RuleEngine.init(&reg);

    // 1. Positive case: TLSv1.3 -> pass
    const pos_input = RuleInput{
        .tls_observation = .{
            .protocol_version = "TLSv1.3",
        },
    };
    const pos_res = engine.evaluateSingle("WS-RULE-TLS-MIN-VERSION", &pos_input).?;
    try testing.expectEqual(RuleOutcome.pass, pos_res.outcome);
    try testing.expect(pos_res.finding == null);

    // 2. Negative case: TLSv1.0 -> fail with finding
    const neg_input = RuleInput{
        .tls_observation = .{
            .protocol_version = "TLSv1.0",
        },
    };
    const neg_res = engine.evaluateSingle("WS-RULE-TLS-MIN-VERSION", &neg_input).?;
    try testing.expectEqual(RuleOutcome.fail, neg_res.outcome);
    try testing.expect(neg_res.finding != null);
    const f = neg_res.finding.?;
    try testing.expectEqualStrings("WS-RULE-TLS-MIN-VERSION", f.rule_id);
    try testing.expectEqual(Severity.high, f.severity);
    try testing.expectEqual(Confidence.confirmed, f.confidence);
    try testing.expectEqualStrings("TLSv1.0", f.evidence);
    try testing.expect(f.limitations.len > 0);
    try testing.expect(std.mem.indexOf(u8, f.cve_disclaimer, "no claim of comprehensive CVE") != null);

    // 3. Inconclusive case: handshake timed out -> inconclusive
    const inc_input = RuleInput{
        .tls_observation = .{
            .protocol_version = "",
            .timed_out = true,
        },
    };
    const inc_res = engine.evaluateSingle("WS-RULE-TLS-MIN-VERSION", &inc_input).?;
    try testing.expectEqual(RuleOutcome.inconclusive, inc_res.outcome);

    // 4. Not applicable case: HTTP input passed to TLS rule -> not_applicable
    const na_input = RuleInput{
        .http_observation = .{},
    };
    const na_res = engine.evaluateSingle("WS-RULE-TLS-MIN-VERSION", &na_input).?;
    try testing.expectEqual(RuleOutcome.not_applicable, na_res.outcome);
}

test "rules engine: positive, negative, and not-applicable cases for HTTP CSP" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();
    const engine = RuleEngine.init(&reg);

    // 1. Positive case: HTML document with strict CSP
    const pos_input = RuleInput{
        .http_observation = .{
            .is_https = true,
            .is_html = true,
            .is_json_api = false,
            .csp_header = "default-src 'self'; script-src 'self' https://trusted.org",
        },
    };
    const pos_res = engine.evaluateSingle("WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION", &pos_input).?;
    try testing.expectEqual(RuleOutcome.pass, pos_res.outcome);

    // 2. Negative case: HTML document with unsafe-inline
    const neg_input = RuleInput{
        .http_observation = .{
            .is_https = true,
            .is_html = true,
            .is_json_api = false,
            .csp_header = "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
    };
    const neg_res = engine.evaluateSingle("WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION", &neg_input).?;
    try testing.expectEqual(RuleOutcome.fail, neg_res.outcome);
    try testing.expect(neg_res.finding != null);

    // 3. Not applicable case: JSON API without CSP is not flagged
    const json_input = RuleInput{
        .http_observation = .{
            .is_https = true,
            .is_html = false,
            .is_json_api = true,
            .csp_header = null,
        },
    };
    const na_res = engine.evaluateSingle("WS-RULE-HTTP-CSP-SCRIPT-RESTRICTION", &json_input).?;
    try testing.expectEqual(RuleOutcome.not_applicable, na_res.outcome);
}

test "rules engine: listener exposure positive, negative, and permission-limited cases" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();
    const engine = RuleEngine.init(&reg);

    // 1. Positive case: Loopback listener
    const loop_input = RuleInput{
        .listener_observation = .{
            .address = "127.0.0.1",
            .port = 8080,
            .binding_type = "loopback",
        },
    };
    const loop_res = engine.evaluateSingle("WS-RULE-EXPOSURE-WILDCARD-BINDING", &loop_input).?;
    try testing.expectEqual(RuleOutcome.pass, loop_res.outcome);

    // 2. Negative case: Wildcard listener 0.0.0.0:80
    const wild_input = RuleInput{
        .listener_observation = .{
            .address = "0.0.0.0",
            .port = 80,
            .binding_type = "wildcard",
        },
    };
    const wild_res = engine.evaluateSingle("WS-RULE-EXPOSURE-WILDCARD-BINDING", &wild_input).?;
    try testing.expectEqual(RuleOutcome.fail, wild_res.outcome);
    try testing.expect(wild_res.finding != null);

    // 3. Inconclusive case: Permission limited socket access
    const perm_input = RuleInput{
        .listener_observation = .{
            .address = "127.0.0.1",
            .port = 8080,
            .permission_limited = true,
        },
    };
    const perm_res = engine.evaluateSingle("WS-RULE-EXPOSURE-WILDCARD-BINDING", &perm_input).?;
    try testing.expectEqual(RuleOutcome.inconclusive, perm_res.outcome);
}

test "rules engine: baseline deviation positive, negative, and inconclusive cases" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();
    const engine = RuleEngine.init(&reg);

    // 1. Positive case: Observed item matches baseline
    const pos_input = RuleInput{
        .baseline_observation = .{
            .item_id = "tcp:443",
            .baseline_value = "nginx/1.24.0",
            .current_value = "nginx/1.24.0",
            .is_new = false,
            .is_removed = false,
        },
    };
    const pos_res = engine.evaluateSingle("WS-RULE-BASELINE-UNEXPECTED-SERVICE", &pos_input).?;
    try testing.expectEqual(RuleOutcome.pass, pos_res.outcome);

    // 2. Negative case: New unbaselined service
    const neg_input = RuleInput{
        .baseline_observation = .{
            .item_id = "tcp:8080",
            .is_new = true,
        },
    };
    const neg_res = engine.evaluateSingle("WS-RULE-BASELINE-UNEXPECTED-SERVICE", &neg_input).?;
    try testing.expectEqual(RuleOutcome.fail, neg_res.outcome);
    try testing.expect(neg_res.finding != null);

    // 3. Inconclusive case: Incomplete observation does not claim removal
    const inc_input = RuleInput{
        .baseline_observation = .{
            .item_id = "tcp:443",
            .is_removed = true,
            .evidence_incomplete = true,
        },
    };
    const inc_res = engine.evaluateSingle("WS-RULE-BASELINE-SERVICE-REMOVED", &inc_input).?;
    try testing.expectEqual(RuleOutcome.inconclusive, inc_res.outcome);
}

test "rules engine: malformed rules fail safely without panics" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();

    // 1. Invalid rule ID (missing WS-RULE- prefix)
    var malformed1 = BUILTIN_RULES[0];
    malformed1.id = "INVALID-PREFIX";
    try testing.expectError(error.InvalidRuleId, reg.register(malformed1));

    // 2. Invalid rule version (0)
    var malformed2 = BUILTIN_RULES[0];
    malformed2.id = "WS-RULE-TEST";
    malformed2.version = 0;
    try testing.expectError(error.InvalidRuleVersion, reg.register(malformed2));

    // 3. Empty title
    var malformed3 = BUILTIN_RULES[0];
    malformed3.id = "WS-RULE-TEST-EMPTY-TITLE";
    malformed3.title = "";
    try testing.expectError(error.EmptyRuleTitle, reg.register(malformed3));

    // 4. Missing rationale
    var malformed4 = BUILTIN_RULES[0];
    malformed4.id = "WS-RULE-TEST-NO-RATIONALE";
    malformed4.rationale = "";
    try testing.expectError(error.MissingRationale, reg.register(malformed4));

    // 5. Missing limitations
    var malformed5 = BUILTIN_RULES[0];
    malformed5.id = "WS-RULE-TEST-NO-LIMITS";
    malformed5.limitations = "";
    try testing.expectError(error.MissingLimitations, reg.register(malformed5));

    // 6. Missing remediation
    var malformed6 = BUILTIN_RULES[0];
    malformed6.id = "WS-RULE-TEST-NO-REMEDIATION";
    malformed6.remediation = "";
    try testing.expectError(error.MissingRemediation, reg.register(malformed6));
}

test "rules engine: serialization formats (terminal, json, markdown) include CVE disclaimer" {
    var reg = RuleRegistry.init(testing.allocator);
    defer reg.deinit();
    reg.registerDefaults();

    var term_buf: [16384]u8 = undefined;
    var term_fbs = std.io.fixedBufferStream(&term_buf);
    try reg.toTerminal(term_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "WIRESCOPE VERSIONED DEFENSIVE RULES REGISTRY") != null);
    try testing.expect(std.mem.indexOf(u8, term_fbs.getWritten(), "no claim of comprehensive CVE") != null);

    var json_buf: [16384]u8 = undefined;
    var json_fbs = std.io.fixedBufferStream(&json_buf);
    try reg.toJson(json_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "\"registry_type\":\"versioned_rules\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "\"schema_version\":1") != null);
    try testing.expect(std.mem.indexOf(u8, json_fbs.getWritten(), "no claim of comprehensive CVE") != null);

    var md_buf: [16384]u8 = undefined;
    var md_fbs = std.io.fixedBufferStream(&md_buf);
    try reg.toMarkdown(md_fbs.writer());
    try testing.expect(std.mem.indexOf(u8, md_fbs.getWritten(), "# WireScope Versioned Defensive Rules Registry") != null);
    try testing.expect(std.mem.indexOf(u8, md_fbs.getWritten(), "no claim of comprehensive CVE") != null);
}
