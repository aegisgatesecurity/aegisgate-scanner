// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - XSS Request Detection Patterns (Extended)
// =========================================================================
//
// Patterns for detecting XSS payload generation requests in AI prompts.
// These supplement the existing XSS response detection patterns in xss.go.
// Ported from Platform v4.7.0 scanner patterns (Phase 2 expansion).
// =========================================================================

package detectors

// XSSRequestPatterns defines XSS payload generation request detection patterns.
// These are natural-language request patterns, complementing the HTML/JS
// payload patterns in XSSPatterns (xss.go).
var XSSRequestPatterns = []PatternDef{
	{
		Name:        "xss_payload_request",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:cross.?site.?scripting|xss)\s*payload\b|(?i)\b(?:generate|create|write|build)\s+(?:a\s+)?(?:xss|cross.?site.?scripting)\s*payload\b`,
		Description: "XSS payload generation request",
	},
	{
		Name:        "xss_exploit_request",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:an?\s+)?(?:XSS|cross-?site-?scripting)\s+(?:exploit|attack|vector|injection)\b`,
		Description: "XSS exploit/attack generation request",
	},
	{
		Name:        "xss_dom_based",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:DOM-?based\s+XSS|DOM\s+XSS|DOM\s+clobbering)\b`,
		Description: "DOM-based XSS request",
	},
	{
		Name:        "xss_innerhtml",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:innerHTML\s+(?:manipulation|injection|exploit)|XSS\s+(?:vector|payload).{0,20}innerHTML)\b`,
		Description: "innerHTML XSS manipulation",
	},
	{
		Name:        "xss_stored_reflected",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:stored|reflected|blind)\s+XSS\s+(?:payload|exploit|attack|injection)\b`,
		Description: "Stored/reflected/blind XSS request",
	},
	{
		Name:        "xss_csp_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:XSS|cross-?site-?scripting)\s+payload.{0,30}(?:bypass|evade|circumvent)\s+CSP\b`,
		Description: "XSS payload with CSP bypass",
	},
	{
		Name:        "xss_attack_for_target",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:an?\s+)?(?:XSS|cross-?site-?scripting)\s+attack\s+for\s+(?:the\s+)?(?:profile|message|login|search|comment|forum|board|page|form)\b`,
		Description: "XSS attack targeting specific page/component",
	},
	{
		Name:        "xss_script_tag_injection",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?script\s+tag\s+injection\b`,
		Description: "Script tag injection request",
	},
	{
		Name:        "xss_exploit_using",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:an?\s+)?(?:XSS|cross-?site-?scripting)\s+(?:exploit|attack)\s+using\b`,
		Description: "XSS exploit using specific technique (SVG, foreignObject, etc.)",
	},
}

// CompiledXSSRequestPatterns holds pre-compiled XSS request regex patterns.
var CompiledXSSRequestPatterns []compiledPattern

func init() {
	CompiledXSSRequestPatterns = compilePatterns(XSSRequestPatterns)
}

// DetectXSSRequest scans text for XSS payload generation request patterns.
func DetectXSSRequest(text string) []Match {
	return detectWithPatterns(text, CompiledXSSRequestPatterns, string(CategoryXSS))
}
