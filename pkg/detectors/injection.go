// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - SQL Injection Detection Patterns
// =========================================================================
//
// Patterns for detecting SQL injection requests in AI prompts.
// Ported from Platform v4.7.0 scanner patterns (Phase 2 expansion).
// =========================================================================

package detectors

// InjectionPatterns defines SQL injection detection patterns.
var InjectionPatterns = []PatternDef{
	{
		Name:        "mass_pii_retrieval",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:retrieve|access|fetch|pull|get|export|dump|extract|download|query|return|output|list|show|display|collect|gather|harvest)\b.{0,80}\b(?:all|every|entire|complete|full)\b.{0,80}\b(?:SSNs?|social\s+security|credit\s+cards?|card\s+numbers?|CVVs?|PINs?|passwords?|passports?|driver'?s?\s+licenses?|dates?\s+of\s+birth|DOBs?|bank\s+accounts?|routing\s+numbers?|national\s+IDs?)\b`,
		Description: "Mass PII retrieval request — bulk data collection specifying sensitive PII types",
	},
	{
		Name:        "sqli_payload_request",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:sql\s*injection\s*(?:payload|attack|query|exploit|vector)|injection\s*payload.{0,30}bypass(?:es)?\s*(?:waf|filter|firewall)|sqli\s*payload)\b`,
		Description: "SQL injection payload request",
	},
	{
		Name:        "sqli_waf_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:bypass(?:es)?\s*(?:waf|web\s*application\s*firewall|filter|detection)|waf\s*bypass|filter\s*evasion.{0,30}sql)\b`,
		Description: "SQL injection WAF bypass request",
	},
	{
		Name:        "sqli_drop_table",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:drop\s+(?:all\s+)?tables?\s+(?:in|from)\s+(?:the\s+)?(?:production|prod|database|db)|drop\s+database|truncate\s+(?:all|every)\s+tables?|delete\s+from\s+\*\s*|delete\s+from\s+(?:all|every)\s+tables?)\b`,
		Description: "Destructive SQL (DROP/TRUNCATE/DELETE all tables)",
	},
	{
		Name:        "sqli_data_extraction",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:extract.{0,30}(?:credit\s*card|ssn|password|credential|personal|sensitive|private).{0,30}(?:from\s+)?(?:the\s+)?(?:database|db|table)|dump\s+(?:the\s+)?(?:database|db|table|users?|passwords)|exfiltrat\w*\s+data.{0,30}(?:database|sql|table))\b`,
		Description: "SQL data extraction/exfiltration request",
	},
	{
		Name:        "sqli_union_select",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:['";]?)\s*union\s+(?:all\s+)?select\b.{0,100}(?:information_schema|from\s+users|--|#|/\*\*/|null|concat|@@version|version\(\)|database\(\)|sleep\()|(?i)\b(?:select|insert|update|delete|drop|alter|create)\b.{0,50}\bfrom\b.{0,100}\b(?:information_schema|mysql\.|pg_|sys\.|master\.)\b`,
		Description: "UNION SELECT with injection indicators or information_schema access",
	},
	{
		Name:        "sqli_boolean_based",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|and\s+'1'\s*=\s*'1'|or\s+true|and\s+false)\b`,
		Description: "Boolean-based SQL injection",
	},
	{
		Name:        "sqli_time_based",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:(?:['";]\s*)?(?:and|or)\s+)?sleep\s*\(\s*\d+\s*\)\s*(?:--|#|/\*|;)|\b(?:and|or|union)\s+sleep\s*\(\s*\d+\s*\)|\b(?:waitfor\s+delay\s+['"]|benchmark\s*\(|pg_sleep\s*\()`,
		Description: "Time-based blind SQL injection",
	},
	{
		Name:        "sqli_stacked_queries",
		Severity:    SeverityHigh,
		Regex:       `(?i);\s*(?:drop|delete|update|insert|alter|create|truncate)\s+`,
		Description: "Stacked SQL query injection",
	},
	{
		Name:        "sqli_comment_evasion",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:--|/\*|\#).{0,20}(?:drop|delete|select|insert|update|union|exec)`,
		Description: "SQL comment-based evasion",
	},
	{
		Name:        "sqli_generic_request",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:generate|write|create|build|construct)\s+(?:a\s+)?sql\s*(?:query|statement|injection).{0,50}(?:extract|steal|dump|bypass|drop|delete|attack|exploit)`,
		Description: "Generic SQL injection generation request",
	},
	{
		Name:        "sqli_union_select_tuned",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bunion\s+(?:all\s+)?select\b.{0,80}(?:from\s+users|information_schema|@@version|sleep\(|concat\(|null,\s*null)`,
		Description: "UNION SELECT injection targeting users table or schema",
	},
	{
		Name:        "sqli_stacked_queries_gen",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:generate|write|create|build)\s+(?:a\s+)?(?:stacked\s+sql\s+queries|sql\s+queries)\s+to\s+(?:drop|delete|update|modify)\s+(?:multiple|all|several)\s+tables?\b`,
		Description: "Stacked SQL queries generation to drop tables",
	},
	{
		Name:        "sqli_blind_script",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:create|write|generate|build)\s+(?:a\s+)?blind\s+sql\s+injection\s+script\b`,
		Description: "Blind SQL injection script generation",
	},
	{
		Name:        "sqli_red_team_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:as\s+part\s+of\s+(?:a|an)\s+(?:red\s+team|penetration\s+test|security\s+assessment).{0,50}(?:generate|write|create)\s+sql\s+to\s+(?:bypass|evade|circumvent)\s+(?:the\s+)?(?:WAF|web\s+application\s*firewall|filter|detection))\b`,
		Description: "Red team SQL WAF bypass request",
	},
	{
		Name:        "sqli_alter_schema",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:alter\s+table.{0,30}(?:corrupt|damage|modify|destroy|drop|truncate)|write\s+sql\s+to\s+alter\s+table)\b`,
		Description: "SQL ALTER TABLE schema corruption",
	},
	{
		Name:        "sqli_copy_to_external",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:create|write|generate|build)\s+(?:a\s+)?sql\s+to\s+(?:copy|move|transfer|export)\s+(?:all\s+)?(?:credit\s*card|customer|user|financial|payment)\s+data\s+to\s+(?:an?\s+)?(?:external|outside|remote|third.?party)\s+table\b`,
		Description: "SQL to copy sensitive data to external table",
	},
	{
		Name:        "sqli_dump_passwords",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:write|generate|create)\s+sql\s+to\s+(?:dump|extract|steal|export)\s+(?:all\s+)?(?:passwords|credentials|usernames|emails?|credit\s*cards?|ssns?).{0,30}(?:from\s+(?:the\s+)?(?:users?|accounts?|customers?)\s+table)`,
		Description: "SQL to dump passwords from users table",
	},
}

// CompiledInjectionPatterns holds pre-compiled injection regex patterns.
var CompiledInjectionPatterns []compiledPattern

func init() {
	CompiledInjectionPatterns = compilePatterns(InjectionPatterns)
}

// DetectInjection scans text for all SQL injection patterns and returns matches.
func DetectInjection(text string) []Match {
	return detectWithPatterns(text, CompiledInjectionPatterns, string(CategoryInjection))
}
