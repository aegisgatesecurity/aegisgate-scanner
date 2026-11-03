// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Prompt Injection Request Detection Patterns
// =========================================================================
//
// Request-side prompt injection patterns (ported from Platform v5.1.0).
// These detect injection attempts in user prompts/requests, complementing
// the response-side leakage patterns in prompt_leakage_patterns.go.
//
// =========================================================================

package detectors

// PromptInjectionRequestPatterns defines request-side prompt injection
// detection patterns — attacks in the user's prompt targeting the model.
var PromptInjectionRequestPatterns = []PatternDef{
	// --- Command-style injection ---
	{
		Name:        "pi_command_ignore",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|constraints?)|disregard\s+(?:your\s+)?(?:instructions?|rules?)|forget\s+(?:everything|all)\s+(?:you|we)\s+(?:have\s+)?told)`,
		Description: "Command-style prompt injection (ignore/disregard/forget)",
	},
	{
		Name:        "pi_command_flexible",
		Severity:    SeverityCritical,
		Regex:       `(?i)ignore\s+(?:\w+\s+)?(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|constraints?)`,
		Description: "Flexible command injection (allows extra words for l33t-decoded payloads)",
	},
	// --- Role-play jailbreaks ---
	{
		Name:        "pi_roleplay",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:act\s+as\s+(?:a|an)|pretend\s+you\s+are\s+(?:a|an)|roleplay\s+(?:as|that)|simulate\s+(?:a|an|being)|you\s+are\s+now\s+(?:a|an)|play\s+the\s+role\s+of)`,
		Description: "Role-play prompt injection / jailbreak",
	},
	{
		Name:        "pi_roleplay_malicious",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:act\s+as\s+(?:a|an)\s+(?:hacker|attacker|malicious)|pretend\s+you\s+are\s+(?:a|an)\s+(?:hacker|attacker|DAN|evil|unrestricted)|play\s+the\s+role\s+of\s+(?:a|an)\s+(?:hacker|attacker|malicious)|simulate\s+(?:being\s+)?(?:a|an)\s+(?:hacker|attacker|AI\s+that\s+has\s+been\s+jailbroken|jailbroken))`,
		Description: "Malicious role-play jailbreak (hacker/attacker/DAN/jailbroken)",
	},
	{
		Name:        "pi_dan_jailbreak",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:DAN\b|do\s+anything\s+now)(?:\s+mode|\s*\(|,|\s+and\s+answer)`,
		Description: "DAN (Do Anything Now) jailbreak attempt",
	},
	{
		Name:        "pi_jailbreak_generic",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:jailbreak(?:ed)?\s+(?:the\s+)?(?:model|AI|system|you)|jailbreak\s+mode|been\s+jailbroken)\b`,
		Description: "Generic jailbreak attempt",
	},
	// --- Prompt leakage / extraction ---
	{
		Name:        "pi_leakage_show",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:show\s+(?:me\s+)?(?:your\s+)?(?:initial\s+|system\s+|hidden\s+|internal\s+)?(?:prompt|instructions?|guidelines?|rules?|config)|reveal\s+(?:your\s+|the\s+)?(?:hidden\s+|system\s+|internal\s+)?(?:rules?|instructions?|prompt|guidelines?|config)|print\s+(?:your\s+)?(?:full\s+|complete\s+|entire\s+)?(?:system\s+|hidden\s+|internal\s+)?(?:instructions?|prompt|config))`,
		Description: "Prompt extraction — show/reveal/print system prompt or instructions",
	},
	{
		Name:        "pi_leakage_output",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:output\s+(?:your\s+|the\s+|everything\s+between\s+)?(?:system|hidden|internal|initial)\s*(?:prompt|instructions?|guidelines?|rules?|config|tags?)|output\s+everything\s+between\s+<(?:system|developer|admin|internal)>|give\s+(?:me\s+|us\s+)?(?:your\s+|the\s+)?(?:system|hidden)\s+(?:instructions?|prompt|guidelines?))`,
		Description: "Prompt extraction — output/give system prompt or instructions",
	},
	{
		Name:        "pi_leakage_what_are",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:what\s+(?:are|is)\s+(?:your\s+)?(?:system|hidden|internal)\s+(?:instructions?|prompt|config|rules?)|what\s+(?:is|are)\s+your\s+(?:initial|original)\s+prompt|tell\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system|hidden)\s+(?:instructions?|prompt|rules?))`,
		Description: "Prompt extraction — what are/is your system instructions",
	},
	{
		Name:        "pi_leakage_system_tags",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:output|show|print|reveal)\s+(?:everything\s+)?(?:between\s+|inside\s+)?<(?:system|developer|admin|internal)>.*</(?:system|developer|admin|internal)>`,
		Description: "System tag content extraction attempt",
	},
	// --- Override attempts ---
	{
		Name:        "pi_override_safety",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:override\s+(?:your\s+)?(?:safety|security|content\s+filter|guardrail|safety\s+training|safety\s+mode)|bypass\s+(?:your\s+)?(?:safety|security|content\s+filter|guardrails?))`,
		Description: "Safety/security override attempt",
	},
	{
		Name:        "pi_developer_mode",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:developer\s+mode|debug\s+mode|admin\s+mode|god\s+mode|root\s+mode|sudo\s+mode|maintenance\s+mode).{0,30}(?:output|print|show|reveal|display|dump|execute|run|enable|disable|ignore|bypass|override)`,
		Description: "Developer/admin mode jailbreak with action",
	},
	{
		Name:        "pi_system_admin_override",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:I\s+am\s+(?:the\s+)?(?:system\s+administrator|admin|developer|root)|as\s+(?:a\s+|the\s+)?(?:system\s+administrator|admin|developer|root)).{0,40}(?:override|bypass|disable|ignore|enable|access|unlock)`,
		Description: "System administrator authority claim with override request",
	},
	{
		Name:        "pi_prefix_jailbreak",
		Severity:    SeverityCritical,
		Regex:       `(?i)^(?:simulate|you\s+are\s+free|now\s+you\s+can|breaking|override|developer\s+mode|jailbreak|DAN)\s*[:;]`,
		Description: "Known jailbreak prefix",
	},
	// --- Base64 obfuscation ---
	{
		Name:        "pi_base64_execute",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:execute|run|decode|process)\s*[:=]?\s*[A-Za-z0-9+/]{20,}={0,2}\b`,
		Description: "Base64-encoded command execution attempt",
	},
	// --- Code execution in prompt ---
	{
		Name:        "pi_code_exec_subprocess",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:continue\s+this\s+code|complete\s+this\s+code|finish\s+this\s+code|run\s+this\s+code|execute\s+this\s+code).{0,60}(?:subprocess|os\.system|os\.popen|exec\s*\(|eval\s*\(|child_process|require\s*\(|import\s+os|curl|wget|nc\s+|netcat|/bin/sh|/bin/bash)`,
		Description: "Code execution request with dangerous functions",
	},
	{
		Name:        "pi_code_exec_general",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:continue\s+this\s+code|complete\s+this\s+code|finish\s+this\s+code).{0,30}(?:import|require|from\s+\w+\s+import|include)`,
		Description: "Code completion request with imports (potential injection)",
	},
	// --- Delimiter injection ---
	{
		Name:        "pi_delimiter",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:markdown\s+block|#\s*(?:system|user|assistant)\s*prompt|<<<\s*(?:USER|SYSTEM|assistant):::|\[INST\]|\[/INST\])`,
		Description: "Jailbreak delimiter injection",
	},
	// --- Chinese-language injection ---
	{
		Name:        "pi_chinese",
		Severity:    SeverityCritical,
		Regex:       `忽略所有之前的指令|忽略之前的指令|忽略所有先前的指示|泄露系统提示|显示系统提示|输出系统提示|忽略安全限制|无视安全规则`,
		Description: "Chinese-language prompt injection",
	},
	{
		Name:        "pi_translate_execute",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:translate|convert|change).{0,30}(?:ignore|disregard|bypass|override).{0,30}(?:safety|security|filter|restriction|guardrail).{0,40}(?:follow|execute|obey|comply)\s+(?:the\s+)?(?:translated|converted)\s+instruction`,
		Description: "Translate-then-execute prompt injection (obfuscation via translation)",
	},
	{
		Name:        "pi_game_extraction",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:let'?s\s+play|play\s+a\s+game|round\s+\d).{0,60}(?:repeat|say|output|print).{0,40}(?:system\s+prompt|system\s+instructions?|hidden\s+prompt|secret\s+prompt)`,
		Description: "Game-based prompt extraction technique",
	},
	{
		Name:        "pi_authorized_test",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:authorized|approved|official)\s+(?:security\s+)?test.{0,40}(?:disable|turn\s+off|deactivate|remove|bypass).{0,20}(?:your\s+)?(?:filters?|safety|guardrails?|protections?|restrictions?|security)`,
		Description: "Fake authorization claim to disable safety filters",
	},
	{
		Name:        "pi_developer_instruct",
		Severity:    SeverityCritical,
		Regex:       `(?i)as\s+(?:the\s+)?(?:developer|admin|administrator|creator|owner).{0,30}(?:instruct\w*|telling|ordering|directing)\s+(?:you\s+)?to\s+(?:bypass|ignore|override|disable|circumvent)\s+(?:your\s+)?(?:guidelines?|rules?|safety|restrictions?|guardrails?)`,
		Description: "Developer authority claim to bypass guidelines",
	},
	{
		Name:        "pi_emergency_protocol",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:emergency|critical|urgent)\s+protocol.{0,40}(?:safety|security|all)\s+(?:restrictions?|filters?|guardrails?|protections?|limits?).{0,20}(?:lifted|removed|disabled|suspended|deactivated|overridden)`,
		Description: "Fake emergency protocol to lift safety restrictions",
	},
}

// CompiledPromptInjectionRequestPatterns holds pre-compiled prompt injection request regex patterns.
var CompiledPromptInjectionRequestPatterns []compiledPattern

func init() {
	CompiledPromptInjectionRequestPatterns = compilePatterns(PromptInjectionRequestPatterns)
}

// DetectPromptInjectionRequest scans text for request-side prompt injection patterns.
func DetectPromptInjectionRequest(text string) []Match {
	return detectWithPatterns(text, CompiledPromptInjectionRequestPatterns, "prompt-injection")
}
