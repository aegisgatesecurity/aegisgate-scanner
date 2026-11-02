// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Data Exfiltration & Insider Threat Patterns
// =========================================================================
//
// Patterns for detecting data exfiltration and insider threat requests
// in AI prompts. Ported from Platform v4.7.0 scanner patterns.
// =========================================================================

package detectors

// DataExfilPatterns defines data exfiltration and insider threat detection patterns.
var DataExfilPatterns = []PatternDef{
	// Sensitive file access requests
	{
		Name:        "exfil_sensitive_file_read",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:read|show|display|output|print|reveal|cat|view|dump|include).{0,30}(?:contents?\s+of\s+)?(?:/etc/(?:passwd|shadow|hosts|sudoers|group|gshadow)|/root/\.ssh/|~/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|~/\.aws/credentials|~/\.aws/config|~/\.git-credentials|~/\.npmrc|~/\.pypirc|~/\.docker/config|/proc/self/environ)`,
		Description: "Request to read sensitive system/credential files",
	},
	{
		Name:        "exfil_ssh_key",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:read|show|display|output|print|reveal|include).{0,30}(?:the\s+)?(?:file\s+at\s+)?(?:/root/\.ssh/|~/\.ssh/|/home/\w+/\.ssh/).{0,30}(?:id_rsa|id_ed25519|id_ecdsa|identity|private\s*key)\b`,
		Description: "SSH private key extraction request",
	},
	{
		Name:        "exfil_env_var",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:output|show|display|print|reveal|give\s+me|tell\s+me|what\s+is|dump).{0,20}(?:the\s+)?(?:value\s+of\s+)?(?:the\s+)?(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|PASSWORD|DB_PASSWORD|DATABASE_URL|REDIS_URL|JWT_SECRET|ENCRYPTION_KEY|AWS_SECRET|OPENAI_API_KEY)\s+(?:environment\s+variable|env\s+var|in\s+(?:the\s+)?env)|env\s*(?:var|variable)\s+(?:API_KEY|SECRET|TOKEN|PASSWORD)`,
		Description: "Environment variable extraction request",
	},
	{
		Name:        "exfil_cloud_creds",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:list|show|read|display|output|dump|reveal|extract|print).{0,20}(?:all\s+)?(?:AWS|Azure|GCP|Google).{0,20}(?:credentials?|keys?|tokens?|secrets?).{0,30}(?:in\s+|from\s+|at\s+)?(?:~/\.aws/|~/\.azure/|~/\.config/gcloud/|credentials\s+file|config\s+file)`,
		Description: "Cloud credential file access request",
	},
	{
		Name:        "exfil_config_secrets",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:dump|read|show|display|output|extract|reveal).{0,30}(?:the\s+)?(?:database\s+connection\s+(?:string|url|dsn)|db\s+connection\s+string|connection\s+string.{0,20}(?:from|in)\s+config|secrets?.{0,20}(?:from|in)\s+(?:config|\.env|yaml|yml|json|properties))\b`,
		Description: "Configuration file secret extraction",
	},
	{
		Name:        "exfil_external_transfer",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:send|transfer|upload|post|transmit|exfiltrat\w*|pipe|forward).{0,30}(?:data|files?|records?|credentials?|secrets?|keys?|customer\s+data|PII|PHI|source\s+code|database\s+dump).{0,30}(?:to\s+|via\s+)(?:external|outside|attacker|evil|pastebin|webhook|discord|telegram|ftp|s3|bucket|email|slack)\b`,
		Description: "Data exfiltration to external destination",
	},
	{
		Name:        "exfil_bulk_access",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:dump|export|extract|download|copy|scrape|bulk\s+(?:export|download|extract|copy)).{0,30}(?:all|every|entire|whole|complete)\s+(?:customer|user|employee|patient|financial|medical|database|table|records?|data)\b`,
		Description: "Bulk data access/export request (insider threat indicator)",
	},
	{
		Name:        "exfil_staging",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:compress|archive|zip|tar|encrypt|bundle|package).{0,30}(?:all|every|entire|sensitive|confidential|proprietary).{0,30}(?:data|files?|records?|documents?|source\s+code|database).{0,30}(?:for\s+(?:transfer|exfil|upload|sending|download)|before\s+(?:sending|uploading|transferring))\b`,
		Description: "Data staging for exfiltration (insider threat indicator)",
	},
	{
		Name:        "exfil_out_of_scope",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:access|query|retrieve|view|read|export|download|copy|dump|extract).{0,30}(?:production|prod|customer|financial|salary|hr|employee|patient).{0,30}(?:database|data|records?).{0,30}(?:from\s+(?:my\s+)?(?:personal|home|unauthorized|unapproved)\s+(?:device|machine|computer|laptop|phone|usb|drive)|to\s+(?:my\s+)?(?:personal|home|unauthorized)\s+(?:device|machine|computer|laptop|phone|usb|drive)|using\s+(?:my\s+)?(?:personal|unapproved|unauthorized)\s+(?:device|machine|computer|laptop|phone)|on\s+(?:an\s+)?(?:unapproved|unauthorized)\s+(?:device|machine))\b`,
		Description: "Out-of-scope data access (insider threat indicator)",
	},
	{
		Name:        "exfil_cred_sharing",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:share|send|email|message|post|paste|leak|give).{0,20}(?:my\s+|the\s+|our\s+)?(?:credentials?|passwords?|api\s+keys?|tokens?|secrets?|access\s+keys?|private\s+keys?|admin\s+password).{0,30}(?:with\s+|to\s+)(?:external|third.?party|outside|unauthorized|unknown|someone|anyone|public|rival|competitor|journalist)\b`,
		Description: "Credential sharing with external parties",
	},
	// Insider threat patterns
	{
		Name:        "insider_source_code_theft",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:copy|download|take|steal|extract|mirror).{0,20}(?:the\s+)?(?:source\s+code|codebase|repository|proprietary\s+(?:algorithm|code|models?|IP)).{0,30}(?:to\s+|for\s+|and\s+share\s+with\s+)(?:USB|personal|external|public\s+GitHub|competitor|next\s+job|side\s+business|startup|rival)\b`,
		Description: "Source code/IP theft for external use",
	},
	{
		Name:        "insider_data_leak",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:leak|post|share|send|publish|mirror|upload).{0,20}(?:merger|acquisition|financial|proprietary|confidential|internal|trade\s+secret|penetration\s+test).{0,30}(?:to\s+|with\s+)(?:journalist|public|rival|competitor|external|website|wiki|blog)\b`,
		Description: "Confidential data leak to external party",
	},
	{
		Name:        "insider_unauthorized_use",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:use|access|export|download|copy).{0,20}(?:company|corporate|employer|internal).{0,20}(?:API\s+key|credentials?|database|customer\s+(?:list|data|contact)).{0,30}(?:for\s+|to\s+)(?:my\s+|a\s+)?(?:side\s+business|startup|personal|own|next\s+job|competitor)\b`,
		Description: "Unauthorized use of company resources",
	},
	{
		Name:        "insider_download_unauth",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:download|copy|export|extract|take).{0,20}(?:customer|employee|salary|financial|patient|user).{0,20}(?:list|data|records?|database).{0,30}(?:without\s+(?:authorization|approval|permission)|to\s+(?:work\s+from\s+home|personal|home))\b`,
		Description: "Unauthorized data download",
	},
	{
		Name:        "insider_screenshot_exfil",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:screenshot|capture|photograph).{0,20}(?:internal|confidential|proprietary|wiki|dashboard|screen).{0,20}(?:and\s+)?(?:post|share|send|upload|email).{0,20}(?:externally|outside|public|external)\b`,
		Description: "Screenshot exfiltration of internal systems",
	},
}

// CompiledDataExfilPatterns holds pre-compiled data exfiltration regex patterns.
var CompiledDataExfilPatterns []compiledPattern

func init() {
	CompiledDataExfilPatterns = compilePatterns(DataExfilPatterns)
}

// DetectDataExfil scans text for all data exfiltration patterns and returns matches.
func DetectDataExfil(text string) []Match {
	return detectWithPatterns(text, CompiledDataExfilPatterns, string(CategoryDataExfil))
}
