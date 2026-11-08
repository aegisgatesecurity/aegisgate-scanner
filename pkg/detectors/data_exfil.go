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
		Regex:       `(?i)\b(?:send|transfer|upload|post|transmit|exfiltrat\w*|pipe|forward).{0,30}(?:data|files?|records?|credentials?|secrets?|keys?|customer\s+data|PII|PHI|source\s+code|database\s+dump).{0,30}(?:to\s+|via\s+)(?:\w+\s+){0,3}(?:external|outside|attacker|evil|pastebin|webhook|discord|telegram|ftp|s3|bucket|email|slack)\b`,
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
		Regex:       `(?i)\b(?:compress|archive|zip|tar|encrypt|bundle|package).{0,30}(?:all|every|entire|sensitive|confidential|proprietary).{0,30}(?:data|files?|records?|documents?|source\s+code|database).{0,30}(?:for\s+(?:external\s+)?(?:transfer|exfil|upload|sending|download)|before\s+(?:sending|uploading|transferring))\b`,
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
		Regex:       `(?i)\b(?:copy|download|take|steal|extract|mirror).{0,30}(?:the\s+)?(?:source\s+code|codebase|repository|trade\s+secrets?|proprietary\s+(?:algorithm|code|models?|IP)).{0,30}(?:to\s+(?:share\s+with\s+)?|for\s+|and\s+share\s+with\s+)(?:a\s+|an\s+|the\s+|my\s+)?(?:USB|personal|external|public\s+GitHub|competitor|next\s+job|side\s+business|startup|rival)\b`,
		Description: "Source code/IP theft for external use",
	},
	{
		Name:        "insider_data_leak",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:leak|post|share|send|publish|mirror|upload|copy).{0,30}(?:merger|acquisition|financial|proprietary|confidential|internal|trade\s+secrets?|penetration\s+test).{0,30}(?:to\s+|with\s+)(?:a\s+|an\s+|the\s+)?(?:journalist|public|rival|competitor|external|website|wiki|blog)\b`,
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
	{
		Name:        "insider_encode_exfil",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:base64\s+encode|encode|encrypt|obfuscate).{0,30}(?:the\s+)?(?:credentials?|passwords?|API\s+keys?|tokens?|secrets?|data|files?).{0,30}(?:before\s+(?:sending|transferring|exfiltrating|uploading)|for\s+(?:exfiltration|transfer|sending))\b`,
		Description: "Encoding credentials for exfiltration",
	},
	{
		Name:        "exfil_extract_api_key_config",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:extract|read|show|get|pull).{0,30}(?:the\s+)?(?:Stripe|AWS|Azure|GCP|GitHub|Slack|Twilio|SendGrid|PayPal|OpenAI|Anthropic)\s+(?:API\s+key|secret\s+key|access\s+key|token|credential).{0,30}(?:from\s+(?:the\s+)?(?:application|app|server|config|configuration|env|environment))\b`,
		Description: "Extract API key from application configuration",
	},
	{
		Name:        "exfil_bundle_pii_zip",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:bundle|package|zip|compress|archive).{0,30}(?:all\s+)?(?:customer|user|employee|patient).{0,20}(?:PII|PHI|data|records?|information).{0,30}(?:into\s+(?:a\s+)?(?:zip|tar|archive|file)|for\s+(?:exfiltration|exfil|transfer))\b`,
		Description: "Bundle PII into archive for exfiltration",
	},
	{
		Name:        "exfil_read_db_password_config",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:read|get|show|extract|find).{0,30}(?:the\s+)?database\s+password.{0,30}(?:from\s+(?:config|configuration|yaml|yml|json|properties|env))\b`,
		Description: "Read database password from config file",
	},
	{
		Name:        "insider_export_startup",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:export|download|copy|extract|take).{0,30}(?:the\s+)?(?:customer|client|user).{0,30}(?:contact|email|mailing).{0,30}(?:list|database|records?).{0,30}(?:for\s+(?:my\s+|a\s+)?(?:startup|side\s+business|personal\s+business|own\s+business|new\s+company))\b`,
		Description: "Exporting customer data for personal business",
	},
	{
		Name:        "insider_upload_personal_cloud",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:upload|transfer|copy|sync|move).{0,30}(?:customer|employee|patient|user|company|corporate|production).{0,30}(?:data|records?|database|files?).{0,30}(?:to\s+(?:my\s+|a\s+)?(?:personal|private)\s+(?:AWS\s+S3|S3|bucket|Dropbox|Google\s+Drive|OneDrive|iCloud|GitHub|Azure|GCS|cloud))\b`,
		Description: "Uploading company data to personal cloud storage",
	},
	{
		Name:        "exfil_dropbox_transfer",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:transfer|upload|send|copy|move).{0,30}(?:financial|customer|employee|patient|proprietary|confidential).{0,20}(?:records?|data|files?|documents?).{0,30}(?:to\s+(?:an?\s+)?(?:external\s+)?Dropbox|to\s+(?:my\s+)?personal\s+Dropbox)\b`,
		Description: "Transfer records to external Dropbox",
	},
	{
		Name:        "exfil_redis_config_url",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:show|get|read|extract|reveal|display|tell\s+me)\s+(?:me\s+)?(?:the\s+)?(?:redis|mongo|mysql|postgres|postgresql|amqp|rabbitmq)\s+connection\s+(?:url|string|dsn).{0,30}(?:from\s+|in\s+)(?:the\s+)?(?:config|configuration|env|environment)\b`,
		Description: "Database connection URL extraction from config",
	},
	{
		Name:        "exfil_steganography",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:use|employ|apply)\s+steganograph\w*\s+to\s+(?:hide|conceal|embed|encode)\s+(?:the\s+)?(?:exfiltrat\w+|stolen|sensitive|confidential)\s+data\s+in\s+(?:images?|files?|media)\b`,
		Description: "Steganography for data exfiltration concealment",
	},
	{
		Name:        "insider_download_train_own",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:download|copy|take|extract).{0,30}(?:proprietary|company|internal|corporate).{0,30}(?:models?|algorithms?|code|source\s+code|ML\s+models?|AI\s+models?|datasets?).{0,40}(?:to\s+(?:train|build|start)\s+(?:my\s+|own|a\s+)?(?:own|personal|AI|model|startup|business))\b`,
		Description: "Downloading proprietary models for personal use",
	},
	{
		Name:        "exfil_dump_prod_db",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:dump|export|extract|copy|backup).{0,30}(?:the\s+)?(?:entire\s+|whole\s+|full\s+)?production\s+(?:database|db).{0,20}(?:to\s+(?:a\s+)?(?:file|csv|sql|dump|backup))\b`,
		Description: "Dump production database to file",
	},
	{
		Name:        "insider_unauth_device",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:access|retrieve|read|view|query|download).{0,30}(?:patient|customer|employee|financial|medical|HR|salary).{0,30}(?:records?|data|database).{0,30}(?:on\s+(?:my\s+|an\s+|a\s+)?(?:unauthorized|unapproved|personal|home)\s+(?:phone|device|laptop|computer|machine|USB|drive)|from\s+(?:my\s+|an\s+|a\s+)?(?:unauthorized|unapproved|personal|home)\s+(?:phone|device|laptop|computer|machine))\b`,
		Description: "Accessing records on unauthorized device",
	},
	{
		Name:        "insider_hr_salary_access",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:access|query|read|look\s+up|view|check).{0,30}(?:the\s+)?(?:HR|human\s+resources?|salary|payroll).{0,30}(?:database|records?|data|system).{0,30}(?:to\s+(?:look\s+up|check|view|find)\s+(?:a\s+|my\s+)?(?:coworker|colleague|employee|other)'?s?\s+(?:salary|pay|compensation))\b`,
		Description: "Unauthorized HR/salary database access",
	},
	{
		Name:        "insider_share_third_party",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:share|give|send|provide).{0,30}(?:the\s+|my\s+|our\s+)?(?:admin\s+password|API\s+keys?|credentials?|access\s+keys?|private\s+keys?|secrets?|tokens?).{0,30}(?:to\s+(?:a\s+|an\s+|the\s+)?|with\s+(?:a\s+|an\s+)?)(?:third.?party|external\s+consultant|outside|unauthorized|unknown|someone|anyone|rival|competitor|journalist)\b`,
		Description: "Sharing credentials with third parties",
	},
	{
		Name:        "insider_stage_stolen",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:stage|store|hide|place|move).{0,30}(?:the\s+)?(?:stolen|exfiltrat\w+|taken).{0,30}(?:data|files?|records?|database).{0,30}(?:in\s+(?:a\s+)?(?:hidden|secret|temporary|tmp)\s+(?:directory|folder|location)|before\s+(?:transfer|exfiltration|sending))\b`,
		Description: "Staging stolen data before exfiltration",
	},
	{
		Name:        "insider_print_take_home",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:print|copy|screenshot).{0,30}(?:all\s+)?(?:employee|customer|patient|user).{0,30}(?:SSNs?|social\s+security|records?|data|PII|PHI).{0,30}(?:and\s+(?:take|bring)\s+(?:it|them\s+)?home|to\s+(?:my\s+)?home|for\s+(?:my\s+)?personal\s+use)\b`,
		Description: "Printing PII to take home",
	},
	{
		Name:        "insider_forward_personal",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:forward|send|email|copy|redirect).{0,30}(?:confidential|internal|proprietary|sensitive|private|company|customer|employee|patient|financial|salary).{0,30}(?:emails?|messages?|documents?|files?|data|database|records?).{0,30}(?:to\s+(?:my\s+|a\s+)?(?:(?:personal|private|home|external)\s+)?(?:gmail|yahoo|hotmail)?\s*(?:email|account|address))\b`,
		Description: "Forwarding confidential data to personal account",
	},
	{
		Name:        "insider_dns_tunnel",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:exfiltrat\w+|transfer|send|extract).{0,30}(?:the\s+)?(?:customer|user|employee|company|database).{0,30}(?:database|data|records?).{0,30}(?:via\s+(?:DNS\s+tunneling|DNS\s+queries|ICMP|covert\s+channel)|using\s+DNS\s+tunnel)\b`,
		Description: "DNS tunneling data exfiltration",
	},
	{
		Name:        "exfil_package_db_dump_competitor",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:package|bundle|prepare|stage).{0,30}(?:the\s+)?database\s+dump.{0,30}(?:for\s+(?:delivery|transfer|sending)\s+to\s+(?:the\s+)?(?:competitor|rival|outside|external|third.?party))\b`,
		Description: "Package database dump for competitor delivery",
	},
	{
		Name:        "exfil_transmit_webhook",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:transmit|send|post|forward|relay|exfiltrat\w*).{0,30}(?:the\s+|all\s+)?(?:API\s+keys?|tokens?|secrets?|credentials?|passwords?).{0,30}(?:to\s+(?:my\s+|a\s+|an\s+)?(?:personal|private|external)\s*(?:webhook|endpoint|URL|server|API))\b`,
		Description: "Transmit credentials to personal webhook endpoint",
	},
	{
		Name:        "exfil_archive_codebase_upload",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:archive|compress|zip|tar|package|bundle).{0,30}(?:the\s+)?(?:entire\s+|whole\s+)?codebase|source\s+code|repository.{0,30}(?:before\s+(?:uploading|sending|pushing)\s+to\s+(?:GitHub|public|external)|for\s+(?:upload|transfer|sharing))\b`,
		Description: "Archive codebase for external upload",
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
