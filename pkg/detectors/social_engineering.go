// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Social Engineering Detection Patterns
// =========================================================================
//
// Patterns for detecting social engineering attack generation requests
// in AI prompts. Ported from Platform v4.7.0 scanner patterns.
// =========================================================================

package detectors

// SocialEngineeringPatterns defines social engineering detection patterns.
var SocialEngineeringPatterns = []PatternDef{
	{
		Name:        "socialeng_phishing_gen",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|draft|build|make)\s+(?:a\s+)?(?:phishing|spear-?phishing)\s+(?:email|message|campaign|template|attack)\b`,
		Description: "Phishing email/message generation request",
	},
	{
		Name:        "socialeng_vishing_smishing",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|draft|build|make)\s+(?:a\s+)?(?:vishing|smishing)\s+(?:script|message|attack|text|sms)\b`,
		Description: "Vishing/smishing generation request",
	},
	{
		Name:        "socialeng_bec",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:business\s+email\s+compromise|BEC\b).{0,30}(?:template|attack|script|message)\b`,
		Description: "Business email compromise request",
	},
	{
		Name:        "socialeng_pretexting",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?(?:pretexting|pretext)\s+(?:script|scenario|story|attack)\b`,
		Description: "Pretexting script generation",
	},
	{
		Name:        "socialeng_whaling",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?whaling\s+(?:email|message|attack|campaign)\b`,
		Description: "Whaling attack generation",
	},
	{
		Name:        "socialeng_baiting",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?baiting\s+(?:message|attack|USB|campaign)\b`,
		Description: "Baiting attack generation",
	},
	{
		Name:        "socialeng_tailgating",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?tailgating\s+(?:social\s+engineering\s+)?(?:script|attack|scenario|technique)\b`,
		Description: "Tailgating social engineering",
	},
	{
		Name:        "socialeng_impersonation",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:phishing|impersonating|spoofing).{0,30}(?:Microsoft\s+365|IT\s+support|HR|helpdesk|bank|paypal|amazon|google|apple|IRS|tax)\b`,
		Description: "Brand impersonation phishing",
	},
	{
		Name:        "socialeng_landing_page",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|create|generate|build|make)\s+(?:a\s+)?phishing\s+(?:landing\s+page|login\s+page|credential\s+harvest\w*\s+page).{0,30}(?:mimic\w*|clone|impersonate|copy|replicate)\b`,
		Description: "Phishing landing page generation",
	},
	{
		Name:        "socialeng_pig_butchering",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:pig\s+butchering|romance\s+scam|investment\s+scam)(?:\s+(?:script|attack|campaign|message|scam))?|(?:script|attack|campaign|message).{0,30}(?:pig\s+butchering|romance\s+scam|investment\s+scam)`,
		Description: "Pig butchering/romance scam generation",
	},
	{
		Name:        "socialeng_physical_access",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:social\s+engineering).{0,30}(?:physical\s+access|building\s+access|badge|entry|bypass\s+security)\b`,
		Description: "Physical access social engineering",
	},
}

// CompiledSocialEngineeringPatterns holds pre-compiled social engineering regex patterns.
var CompiledSocialEngineeringPatterns []compiledPattern

func init() {
	CompiledSocialEngineeringPatterns = compilePatterns(SocialEngineeringPatterns)
}

// DetectSocialEngineering scans text for all social engineering patterns and returns matches.
func DetectSocialEngineering(text string) []Match {
	return detectWithPatterns(text, CompiledSocialEngineeringPatterns, string(CategorySocialEngineering))
}
