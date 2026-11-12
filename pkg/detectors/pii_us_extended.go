// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - US Extended PII Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/pii-us-extended.js (13 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// RE2 does not support lookbehind/lookahead; patterns requiring those
// features have been relaxed (removed lookarounds).
// =========================================================================

package detectors

// PIIUSExtendedPatterns defines extended US and international PII patterns.
// Lens parity: pii-us-extended.js v0.2.0 (13 patterns).
var PIIUSExtendedPatterns = []PatternDef{
	{
		Name:        "pii_credit_card_loose",
		Severity:    SeverityHigh,
		Regex:       `\b\d{12,19}\b`,
		Description: "Credit card number (loose: 12-19 digits, use Luhn validation)",
	},
	{
		Name:        "pii_email_intl",
		Severity:    SeverityMedium,
		Regex:       `[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,24}`,
		Description: "International email (CJK/Hangul/Kana support)",
	},
	{
		Name:     "pii_phone_intl_loose",
		Severity: SeverityMedium,
		// Require at least one separator or + prefix to avoid matching bare digit
		// sequences in code (e.g., hex values, character sets like set('0123456789')).
		Regex:       `\+\d[\d\s\-()]{6,12}\d|\b\d{3}[\s\-()]\d{3,4}[\s\-()]?\d{3,4}\b`,
		Description: "International phone number (requires separators to reduce code FPs)",
	},
	{
		Name:        "pii_phone_intl_strict",
		Severity:    SeverityMedium,
		Regex:       `\+?\d{1,3}[\s\-.()]{1,2}\(?\d{2,4}\)?[\s\-.()]{0,2}\d{3,4}[\s\-.()]{0,2}\d{3,4}`,
		Description: "International phone number (strict: formatted with separators)",
	},
	{
		Name:        "pii_passport_generic",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:passport|license|certificate)\s*[:\#]?\s*[A-Z0-9]{5,8}\d[A-Z0-9]*\b`,
		Description: "Generic passport/ID number (6-9 alphanumeric, requires label)",
	},
	{
		Name:        "pii_id_generic_alphanumeric",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:id|code|number|ref|license|passport|certificate|serial|account)\s*[:\#]?\s*[A-Z0-9]{4,15}\d[A-Z0-9]*\b`,
		Description: "Generic alphanumeric ID (4-15 chars, requires label)",
	},
	{
		Name:        "pii_ssn_fr",
		Severity:    SeverityCritical,
		Regex:       `\b[12]\d{2}\.\d{2}\.\d{2}\.\d{3}\.\d{2}\b|\b\d{3}\.\d{4}\.\d{4}\.\d{2}\b`,
		Description: "French INSEE SSN number",
	},
	{
		Name:        "pii_ssn_ru",
		Severity:    SeverityCritical,
		Regex:       `\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b`,
		Description: "Russian SNILS number",
	},
	{
		Name:        "pii_tax_id_ch",
		Severity:    SeverityHigh,
		Regex:       `\bCHE-\d{3}\.\d{3}\.\d{3}\b`,
		Description: "Swiss UID (CHE-XXX.XXX.XXX)",
	},
	{
		Name:        "pii_letter_only_id",
		Severity:    SeverityHigh,
		Regex:       `\b(?:ID|identifier|reference|ref|customer\s+ID|account\s+ID)\s*(?:is|:|=|#|number)?\s*[A-Z]{8,12}\b`,
		Description: "Pure-letter 8-12 char uppercase ID (requires ID/reference label)",
	},
	{
		Name:        "pii_id_multisegment",
		Severity:    SeverityHigh,
		Regex:       `\b[A-Z][A-Z0-9]{1,7}[-.][A-Z0-9]{0,7}\d[A-Z0-9]*[-.][A-Z0-9]{0,7}\d?[A-Z0-9]*(?:[-.][A-Z0-9]{0,7}\d?[A-Z0-9]*){0,2}\b`,
		Description: "Multi-segment ID code (e.g., SHERZ.790015.S9.027)",
	},
	{
		Name:        "pii_street_intl",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:Bulevardul|Bd\.|Intrarea|Strada|Str\.|Aleea|Piața|Calea)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+Nr\.?\s+\d+\b`,
		Description: "International street address (Romanian, etc.)",
	},
	{
		Name:        "pii_ip_address_v6",
		Severity:    SeverityLow,
		Regex:       `(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}`,
		Description: "IPv6 address",
	},
	{
		Name:        "pii_medicare_number",
		Severity:    SeverityCritical,
		Regex:       `(?i)\bmedicare\s+(?:number|id|card)\s*(?:is|:|=|#)?\s*[0-9A-Z]{2,5}[-\s][0-9A-Z]{2,5}[-\s][0-9A-Z]{2,5}\b`,
		Description: "US Medicare number (alphanumeric with separators)",
	},
	{
		Name:        "pii_vin",
		Severity:    SeverityLow,
		Regex:       `(?i)\b(?:vin|vehicle\s+identification\s+number)\s*(?:is|:|=|#)?\s*[A-HJ-NPR-Z0-9]{17}\b`,
		Description: "Vehicle Identification Number (17 chars, excluding I/O/Q) — public info, logged for audit",
	},
	{
		Name:        "pii_license_plate",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:license|licence)\s+plate\s*(?:is|:|=|#|number)?\s*[A-Z0-9]{1,8}[-\s][A-Z0-9]{1,8}\b`,
		Description: "Vehicle license plate number",
	},
	{
		Name:        "pii_gcp_project_id",
		Severity:    SeverityMedium,
		Regex:       `(?i)\bgcp\s+project\s+(?:id|identifier)\s*(?:is|:|=|#)?\s*[a-z][a-z0-9-]{5,30}\b`,
		Description: "Google Cloud Platform project ID",
	},
	{
		Name:        "pii_mac_address",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bmac\s+address\s*(?:is|:|=|#)?\s*(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`,
		Description: "MAC address (hardware network identifier)",
	},
}

// CompiledPIIUSExtendedPatterns holds pre-compiled US extended PII regex patterns.
var CompiledPIIUSExtendedPatterns []compiledPattern

func init() {
	CompiledPIIUSExtendedPatterns = compilePatterns(PIIUSExtendedPatterns)
}

// DetectPIIUSExtended scans text for all US extended PII patterns and returns matches.
func DetectPIIUSExtended(text string) []Match {
	return detectWithPatterns(text, CompiledPIIUSExtendedPatterns, string(CategoryPIIUSExtended))
}
