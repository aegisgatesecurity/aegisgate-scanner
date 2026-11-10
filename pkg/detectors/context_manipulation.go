// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-rampart/internal/detectors/context_manipulation.go
// =========================================================================
// AegisGate Scanner - Context Manipulation Detection
// =========================================================================
//
// Detects attempts to manipulate conversation context across turns:
// - Conversation reset attacks (clearing history to erase safety constraints)
// - Persona override (hijacking the AI's identity)
// - System prompt extraction
// - Constraint breaking
// - Privilege escalation (admin mode, developer mode)
// - Conflicting instructions
//
// Ported from Rampart's ContextManipulationPatterns (6 regex patterns).
// =========================================================================

package detectors

// CategoryContextManipulation is defined in types.go.

// ContextManipulationPatterns defines the context manipulation detection patterns.
// Only High and Critical severity patterns are included — Medium severity patterns
// (memory manipulation, output manipulation) are too FP-prone for single-turn
// regex detection.
var ContextManipulationPatterns = []PatternDef{
	{
		Name:        "ctx_conversation_reset",
		Severity:    SeverityHigh,
		Regex:       `(?i)(new\s+conversation|start\s+over|clear\s+(conversation|history|context)|forget\s+everything\s+(I|we|you)\s+said)`,
		Description: "Conversation reset attempt",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_persona_override",
		Severity:    SeverityCritical,
		Regex:       `(?i)(you\s+are\s+now|you\s+will\s+behave|from\s+now\s+on|disregard\s+your|ignore\s+your\s+(system|original|primary))`,
		Description: "Persona override attempt",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_system_extraction",
		Severity:    SeverityCritical,
		Regex:       `(?i)(tell\s+me\s+your\s+(system|initial|original)\s+(prompt|instructions|directives)|what\s+(is|are)\s+your\s+(system|initial)|show\s+me\s+your\s+programming)`,
		Description: "System prompt extraction attempt",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_constraint_breaking",
		Severity:    SeverityHigh,
		Regex:       `(?i)(you\s+can\s+(not|never)|you\s+must\s+not|don'?t\s+(limit|restrict)|no\s+(limit|restriction)|break\s+(the|your))`,
		Description: "Constraint breaking attempt",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_privilege_escalation",
		Severity:    SeverityCritical,
		Regex:       `(?i)(admin\s+mode|root\s+access|developer\s+mode|debug\s+mode|superuser|sudo\s+root)`,
		Description: "Privilege escalation attempt",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_conflicting_instructions",
		Severity:    SeverityHigh,
		Regex:       `(?i)(ignore\s+.*(and|but)\s+.*respond|disregard\s+.*(and|but)\s+.*(tell|give)|previous\s+.*(ignore|disregard))`,
		Description: "Conflicting instructions detected",
		Category:    CategoryContextManipulation,
	},
	{
		Name:        "ctx_llama_sys_injection",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:<<\s*SYS\s*>>|<\s*/\s*SYS\s*>|<\s*INST\s*>|<\s*/\s*INST\s*>)`,
		Description: "LLaMA-style <<SYS>> or <<INST>> delimiter injection",
		Category:    CategoryContextManipulation,
	},
}

// CompiledContextManipulationPatterns holds the pre-compiled regex patterns.
var CompiledContextManipulationPatterns []compiledPattern

func init() {
	CompiledContextManipulationPatterns = compilePatterns(ContextManipulationPatterns)
}

// DetectContextManipulation scans text for context manipulation patterns.
func DetectContextManipulation(text string) []Match {
	matches := detectWithPatterns(text, CompiledContextManipulationPatterns, string(CategoryContextManipulation))
	return matches
}
