// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner - Agent Instruction Poisoning Detection Patterns
// =========================================================================
//
// Detects patterns associated with Warden Stealer and similar malware that
// poison AI agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules,
// .codex/config.toml) to redirect API traffic, install malicious packages,
// or exfiltrate credentials.
//
// Threat intelligence source: Warden Stealer IOC analysis (Black October 2026)
// =========================================================================

package detectors

// AgentPoisoningPatterns defines detection patterns for agent instruction
// poisoning attacks. These target files that AI coding assistants read
// automatically (CLAUDE.md, AGENTS.md, .cursorrules, config.toml) where
// attackers embed commands to redirect traffic or steal credentials.
var AgentPoisoningPatterns = []PatternDef{
	// Pattern 1: ANTHROPIC_BASE_URL redirection to attacker server
	// Warden Stealer sets ANTHROPIC_BASE_URL to redirect Claude API calls
	// to an attacker-controlled server, intercepting all API traffic.
	{
		Name:        "agent_poisoning_anthropic_redirect",
		Severity:    SeverityHigh,
		Regex:       `(?i)ANTHROPIC_BASE_URL\s*[=:]\s*['"]?https?://\S+`,
		Description: "ANTHROPIC_BASE_URL redirected to non-Anthropic server (agent instruction poisoning)",
		Category:    CategoryAgentPoisoning,
	},
	// Pattern 2: npm/pip install commands in instruction context
	// Attackers embed package install commands in agent instruction files,
	// tricking the AI into executing them. The instruction-language prefix
	// (run, please, you should, etc.) distinguishes this from legitimate
	// install commands in package.json or Dockerfiles.
	{
		Name:        "agent_poisoning_install_instruction",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:run|execute|please|also|additionally|next|then|you\s+(?:should|must|need\s+to|are\s+required\s+to)|make\s+sure\s+to|remember\s+to|always|before\s+(?:running|starting|deploying)|don'?t\s+forget\s+to)\s.{0,40}(?:npm\s+install|npm\s+add|pip3?\s+install|install\s+(?:the\s+)?npm\s+package)\s+\S+`,
		Description: "Package install command embedded in agent instruction context (npm/pip install in instruction text)",
		Category:    CategoryAgentPoisoning,
	},
	// Pattern 3: ~/.codex/config.toml modification references
	// The .codex/config.toml file controls OpenAI Codex agent behavior.
	// References to modifying this file in agent instruction content is
	// a strong indicator of agent configuration manipulation.
	{
		Name:        "agent_poisoning_codex_config",
		Severity:    SeverityMedium,
		Regex:       `(?i)\.codex[/\\]config\.toml`,
		Description: "Reference to .codex/config.toml (OpenAI Codex agent config manipulation)",
		Category:    CategoryAgentPoisoning,
	},
	// Pattern 4: Environment variable exfiltration instructions
	// Attackers instruct agents to exfiltrate environment variables which
	// typically contain API keys, tokens, and other secrets. Complements
	// the existing atlas_data_exfiltration_query pattern with explicit
	// exfiltration verb + env var targeting.
	{
		Name:        "agent_poisoning_env_exfil",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:exfiltrate|send|transmit|upload|post|leak|forward|pipe)\s+(?:the\s+|all\s+)?(?:environment\s+variables?|env\s+vars?|process\.env|\.env\s+(?:file|contents?))`,
		Description: "Instruction to exfiltrate environment variables (credential theft via agent instructions)",
		Category:    CategoryAgentPoisoning,
	},
	// Pattern 5: function-color npm package IOC
	// function-color is a specific malicious npm package used by Warden
	// Stealer as part of the credential theft payload. Its presence in
	// any file is a strong indicator of compromise.
	{
		Name:        "agent_poisoning_function_color",
		Severity:    SeverityLow,
		Regex:       `(?i)function-color`,
		Description: "function-color npm package reference (Warden Stealer IOC)",
		Category:    CategoryAgentPoisoning,
	},
}

// CompiledAgentPoisoningPatterns holds pre-compiled agent poisoning regex patterns.
var CompiledAgentPoisoningPatterns []compiledPattern

func init() {
	CompiledAgentPoisoningPatterns = compilePatterns(AgentPoisoningPatterns)
}

// DetectAgentPoisoning scans text for all agent instruction poisoning patterns.
func DetectAgentPoisoning(text string) []Match {
	return detectWithPatterns(text, CompiledAgentPoisoningPatterns, string(CategoryAgentPoisoning))
}
