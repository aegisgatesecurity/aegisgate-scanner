// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Secret Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/secrets.js (45 base patterns).
// Extended with additional cloud provider, API, and service credentials (64 total).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// RE2 does not support lookbehind/lookahead; patterns requiring those
// features have been rewritten or relaxed.
// =========================================================================

package detectors

// SecretsPatterns defines all secret detection patterns.
// Lens parity: secrets.js v0.2.0 (45 base patterns), extended to 64.
var SecretsPatterns = []PatternDef{
	{
		Name:        "secret_aws_key",
		Severity:    SeverityCritical,
		Regex:       `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
		Description: "AWS access key ID",
	},
	{
		Name:        "secret_github_token",
		Severity:    SeverityCritical,
		Regex:       `\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b`,
		Description: "GitHub personal access token",
	},
	{
		Name:        "secret_gcp_key",
		Severity:    SeverityHigh,
		Regex:       `\bAIza[0-9A-Za-z_-]{30,50}\b`,
		Description: "Google Cloud API key",
	},
	{
		Name:        "secret_azure_key",
		Severity:    SeverityHigh,
		Regex:       `(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}`,
		Description: "Azure storage account key or SAS",
	},
	{
		Name:        "secret_private_key_pem",
		Severity:    SeverityCritical,
		Regex:       `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`, //nosec G101 -- regex pattern for detecting private keys, not an actual key
		Description: "PEM private key header",
	},
	{
		Name:        "secret_oauth_token",
		Severity:    SeverityHigh,
		Regex:       `\bya29\.[0-9A-Za-z_-]{50,}\b|\b1/[0-9A-Za-z_-]{40,}\b`,
		Description: "OAuth token (Google or generic)",
	},
	{
		Name:        "secret_jwt",
		Severity:    SeverityHigh,
		Regex:       `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
		Description: "JSON Web Token",
	},
	{
		Name:        "secret_api_key_generic",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`,
		Description: "Generic API key or token assignment",
	},
	{
		Name:        "secret_db_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?:mongodb|postgres|postgresql|mysql|redis|amqp)(?:\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+`,
		Description: "Database connection string with credentials",
	},
	{
		Name:        "secret_slack_token",
		Severity:    SeverityHigh,
		Regex:       `\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`,
		Description: "Slack bot/user token",
	},
	{
		Name:        "secret_twilio_key",
		Severity:    SeverityHigh,
		Regex:       `\b(?:SK|AC)[a-fA-F0-9]{32}\b`,
		Description: "Twilio account SID or auth token",
	},
	{
		Name:        "secret_sendgrid_key",
		Severity:    SeverityHigh,
		Regex:       `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
		Description: "SendGrid API key",
	},
	{
		Name:        "secret_mailgun_key",
		Severity:    SeverityHigh,
		Regex:       `\bkey-[a-f0-9]{32}\b`,
		Description: "Mailgun API key",
	},
	{
		Name:        "secret_openai_key",
		Severity:    SeverityHigh,
		Regex:       `\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b`,
		Description: "OpenAI API key",
	},
	{
		Name:        "secret_anthropic_key",
		Severity:    SeverityHigh,
		Regex:       `\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b`,
		Description: "Anthropic API key",
	},
	{
		Name:        "secret_heroku_key",
		Severity:    SeverityMedium,
		Regex:       `\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`,
		Description: "Heroku API key",
	},
	{
		Name:        "secret_gitlab_pat",
		Severity:    SeverityCritical,
		Regex:       `\bglpat-[A-Za-z0-9_-]{20,}\b`,
		Description: "GitLab personal access token",
	},
	{
		Name:        "secret_npm_token",
		Severity:    SeverityCritical,
		Regex:       `\bnpm_[A-Za-z0-9]{30,}\b`,
		Description: "npm access token",
	},
	{
		Name:        "secret_pypi_token",
		Severity:    SeverityCritical,
		Regex:       `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`,
		Description: "PyPI API token",
	},
	{
		Name:        "secret_slack_legacy",
		Severity:    SeverityHigh,
		Regex:       `\bxox[abprs]-[A-Za-z0-9-]{10,}\b`,
		Description: "Slack legacy token",
	},
	{
		Name:        "secret_github_finegrained",
		Severity:    SeverityCritical,
		Regex:       `\bgithub_pat_[A-Za-z0-9_]{60,}\b`,
		Description: "GitHub fine-grained personal access token",
	},
	{
		Name:        "secret_supabase",
		Severity:    SeverityHigh,
		Regex:       `\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b`,
		Description: "Supabase JWT/API key",
	},
	{
		Name:        "secret_db_url_with_password",
		Severity:    SeverityHigh,
		Regex:       `(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+`,
		Description: "Database URL with embedded password",
	},
	{
		Name:        "secret_aws_account_id",
		Severity:    SeverityMedium,
		Regex:       `\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):`,
		Description: "AWS ARN with account ID",
	},
	{
		Name:        "secret_github_actions_token",
		Severity:    SeverityCritical,
		Regex:       `\bgh[osur]_[A-Za-z0-9]{30,}\b`,
		Description: "GitHub Actions token",
	},
	{
		Name:        "secret_gitlab_token",
		Severity:    SeverityCritical,
		Regex:       `(?:GLPAT|gitlab_pat)_[A-Za-z0-9]{20,255}`,
		Description: "GitLab token",
	},
	{
		Name:        "secret_bitbucket_token",
		Severity:    SeverityCritical,
		Regex:       `(?:BITBUCKET_TOKEN|BITBUCKET_PAT)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`,
		Description: "Bitbucket token",
	},
	{
		Name:        "secret_gitea_token",
		Severity:    SeverityCritical,
		Regex:       `gitea_[A-Za-z0-9]{36,255}`,
		Description: "Gitea token",
	},
	{
		Name:        "secret_circleci_token",
		Severity:    SeverityHigh,
		Regex:       `cici_[A-Za-z0-9]{36,255}`,
		Description: "CircleCI token",
	},
	{
		Name:        "secret_travis_token",
		Severity:    SeverityHigh,
		Regex:       `travis_[A-Za-z0-9]{36,255}`,
		Description: "Travis CI token",
	},
	{
		Name:        "secret_jenkins_token",
		Severity:    SeverityHigh,
		Regex:       `(?:JENKINS_TOKEN|JENKINS_API|JENKINS_PASSWORD)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`,
		Description: "Jenkins token",
	},
	{
		Name:        "secret_azure_devops",
		Severity:    SeverityCritical,
		Regex:       `azdo_[A-Za-z0-9]{36,255}`,
		Description: "Azure DevOps token",
	},
	{
		Name:        "secret_digitalocean_token",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:(?:DO_PAT|DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[:=]|DigitalOcean\s+(?:API\s+)?token\s*[:=])\s*dop_v1_[A-Za-z0-9]{30,100}`,
		Description: "DigitalOcean token",
	},
	{
		Name:        "secret_linode_token",
		Severity:    SeverityCritical,
		Regex:       `linode_[A-Za-z0-9]{40,80}`,
		Description: "Linode token",
	},
	{
		Name:        "secret_rackspace_token",
		Severity:    SeverityHigh,
		Regex:       `rackspace_[A-Za-z0-9]{32,64}`,
		Description: "Rackspace token",
	},
	{
		Name:        "secret_heroku_token_legacy",
		Severity:    SeverityHigh,
		Regex:       `heroku_[A-Za-z0-9-]{36,50}`,
		Description: "Heroku legacy token",
	},
	{
		Name:        "secret_salesforce_token",
		Severity:    SeverityCritical,
		Regex:       `00D[A-Za-z0-9]{15}![A-Za-z0-9]{64,128}`,
		Description: "Salesforce session/token",
	},
	{
		Name:        "secret_shopify_token",
		Severity:    SeverityHigh,
		Regex:       `sh[a-z]+_[A-Za-z0-9]{20,255}`,
		Description: "Shopify access token",
	},
	{
		Name:        "secret_wordpress_token",
		Severity:    SeverityHigh,
		Regex:       `wordpress_[A-Za-z0-9]{32,64}`,
		Description: "WordPress application password/token",
	},
	{
		Name:        "secret_internal_api_key",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:INTERNAL[_-]?API[_-]?KEY|INTERNAL[_-]?KEY|INTERNAL[_-]?TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`,
		Description: "Internal API key assignment",
	},
	{
		Name:        "secret_cursor_key",
		Severity:    SeverityHigh,
		Regex:       `\bcrsr_[A-Za-z0-9]{64}\b`,
		Description: "Cursor API key",
	},
	{
		Name:        "secret_vercel_key",
		Severity:    SeverityHigh,
		Regex:       `\bvck[A-Za-z0-9_-]{32,}\b`,
		Description: "Vercel AI Gateway API key",
	},
	{
		Name:        "secret_groq_key",
		Severity:    SeverityHigh,
		Regex:       `\bgsk_[A-Za-z0-9]{52}\b`,
		Description: "Groq API key",
	},
	{
		Name:        "secret_replicate_key",
		Severity:    SeverityHigh,
		Regex:       `\br8_[A-Za-z0-9]{37}\b`,
		Description: "Replicate API token",
	},
	// Phase 3 parity fix — 2026-09-02
	{
		Name:        "pii_german_tax_id",
		Severity:    SeverityHigh,
		Regex:       `\b(?:Steuer-?ID|Steuernummer)[:\s]*\d{11}\b`,
		Description: "German tax identification number (Steuer-ID)",
	},
	// Phase 4 parity fix — 2026-09-24: patterns synced from Platform
	{
		Name:        "SlackToken",
		Severity:    SeverityHigh,
		Regex:       `\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`,
		Description: "Slack token",
	},
	{
		Name:        "SlackTokenV2",
		Severity:    SeverityHigh,
		Regex:       `\bxox[abprs]-[A-Za-z0-9-]{20,}\b`,
		Description: "Slack token (relaxed format)",
	},
	{
		Name:        "secret_azure_connection",
		Severity:    SeverityCritical,
		Regex:       `(?i)Azure\s+connection\s+string\s*[:=]?\s*DefaultEndpointsProtocol=\S+;AccountName=\S+;AccountKey=\S+`,
		Description: "Azure storage connection string",
	},
	{
		Name:        "secret_cloudflare_key",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:cloudflare|cf)[_ \-]?api[_ \-]?key\s*[:=]\s*['"]?([A-Za-z0-9_-]{30,})['"]?`,
		Description: "Cloudflare API key",
	},
	{
		Name:        "secret_docker_pat",
		Severity:    SeverityCritical,
		Regex:       `\bdckr_pat_[A-Za-z0-9_-]{27,}\b`,
		Description: "Docker personal access token",
	},
	{
		Name:        "secret_gcp_key_id",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:private[_-]?key[_-]?id|key[_-]?id)\s*[:=]\s*['"]?([a-fA-F0-9]{8,})['"]?`,
		Description: "GCP service account private key ID",
	},
	{
		Name:        "secret_generic_hex",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:key|secret|token|passphrase|password|api[_-]?key|auth[_-]?token)\s*(?:is|:|=)\s*['"]?([a-fA-F0-9]{32,})['"]?`,
		Description: "Generic hex secret/credential value (32+ hex chars with label)",
	},
	{
		Name:        "secret_kubernetes_token",
		Severity:    SeverityHigh,
		Regex:       `(?i)Kubernetes\s+service\s+account\s+token\s*[:=]?\s*['"]?([A-Za-z0-9+/=_]{20,})['"]?`,
		Description: "Kubernetes service account token",
	},
	{
		Name:        "secret_labeled_credential",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:(?:password|passwd|pwd|secret\s+key|secret|api[_-]?secret|signing[_-]?key|encryption[_-]?key|encryption\s+passphrase|passphrase|auth[_-]?token|access[_-]?key|webhook\s+secret))\s*(?:(?:for\s+\S+(?:\s+\S+){0,3})\s+)?(?:is\s+(?:the\s+)?['"]?(?:[0-9_!@#$%^&*\-+=|<>?./~]\S{3,}|\S[0-9_!@#$%^&*\-+=|<>?./~]\S{2,}|\S{2}[0-9_!@#$%^&*\-+=|<>?./~]\S{1,}|\S{3,}[0-9_!@#$%^&*\-+=|<>?./~]\S*)['"]?|is\s*[:=]\s*['"]?\S{4,}['"]?|[:=]\s*['"]?\S{4,}['"]?)`,
		Description: "Labeled credential value in natural text",
	},
	{
		Name:        "secret_pagerduty_key",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:PagerDuty|pagerduty)\s+(?:API\s+)?key\s*[:=]\s*['"]?(pd_api_key_[A-Za-z0-9_]{20,})['"]?`,
		Description: "PagerDuty API key",
	},
	{
		Name:        "secret_uuid_token",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:consul|vault|nomad)\s+(?:acl\s+)?token\s*(?:is\s+(?:the\s+)?|is\s*[:=]|[:=])?\s*['"]?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b['"]?`,
		Description: "HashiCorp Consul/Vault/Nomad UUID token",
	},
	{
		Name:        "secret_redis_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?i)redis://[^\s"\']+`,
		Description: "Redis connection string",
	},
	{
		Name:        "secret_rsa_private_key",
		Severity:    SeverityCritical,
		Regex:       `-----BEGIN (?:RSA )?PRIVATE KEY-----`, //nosec G101 -- regex pattern for detecting private keys, not an actual key
		Description: "RSA private key",
	},
	{
		Name:        "secret_ec_private_key",
		Severity:    SeverityCritical,
		Regex:       `-----BEGIN EC PRIVATE KEY-----`, //nosec G101 -- regex pattern for detecting private keys, not an actual key
		Description: "EC private key",
	},
	{
		Name:        "secret_openssh_private_key",
		Severity:    SeverityCritical,
		Regex:       `-----BEGIN OPENSSH PRIVATE KEY-----`, //nosec G101 -- regex pattern for detecting private keys, not an actual key
		Description: "OpenSSH private key",
	},
	{
		Name:        "secret_bearer_token",
		Severity:    SeverityMedium,
		Regex:       `\bBearer\s+[a-zA-Z0-9_\-\.]{20,}`,
		Description: "Bearer authentication token",
	},
	{
		Name:        "secret_postgresql_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?i)postgresql://[^\s"\']+`,
		Description: "PostgreSQL connection string",
	},
	{
		Name:        "secret_mysql_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?i)mysql://[^\s"\']+`,
		Description: "MySQL connection string",
	},
	{
		Name:        "secret_mongodb_connection_string",
		Severity:    SeverityHigh,
		Regex:       `(?i)mongodb(\+srv)?://[^\s"\']+`,
		Description: "MongoDB connection string",
	},
	// --- Patterns ported from Rampart + Lens for parity ---
	{
		Name:        "secret_discord_webhook",
		Severity:    SeverityHigh,
		Regex:       `(?i)discord\s+webhook.{0,30}https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+|https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`,
		Description: "Discord webhook URL",
	},
	{
		Name:        "secret_jwt_prefix",
		Severity:    SeverityMedium,
		Regex:       `\beyJhbGci[A-Za-z0-9_-]*`,
		Description: "JWT token prefix (partial match for truncated tokens)",
	},
	{
		Name:        "secret_k8s_token_context",
		Severity:    SeverityHigh,
		Regex:       `(?i)kubernetes\s+(?:service\s+account\s+)?token\s*[:=]\s*[A-Za-z0-9+/=._-]{8,}`,
		Description: "Kubernetes service account token in context",
	},
	{
		Name:        "secret_paypal_token",
		Severity:    SeverityHigh,
		Regex:       `(?i)access_token\$production\$[A-Za-z0-9]+`,
		Description: "PayPal/Braintree access token",
	},
	{
		Name:        "secret_sendgrid_context",
		Severity:    SeverityMedium,
		Regex:       `(?i)sendgrid\s+(?:api\s+)?key\s*[:=]\s*SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		Description: "SendGrid API key mentioned in context",
	},
	{
		Name:        "secret_slack_webhook_url",
		Severity:    SeverityHigh,
		Regex:       `https://hooks\.slack\.com/services/[A-Za-z0-9/]+`,
		Description: "Slack webhook URL",
	},
	{
		Name:        "secret_square_token",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bsq0atp-[A-Za-z0-9_-]{20,}\b|\bsq0csp-[A-Za-z0-9_-]{40,}\b`,
		Description: "Square access token or client secret",
	},
	{
		Name:        "secret_twilio_sid_context",
		Severity:    SeverityMedium,
		Regex:       `(?i)twilio\s+(?:account\s+)?SID\s+(?:is|:)\s*AC[A-Za-z0-9]{10,}`,
		Description: "Twilio account SID in context",
	},
	{
		Name:        "secret_stripe_key",
		Severity:    SeverityCritical,
		Regex:       `\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b`,
		Description: "Stripe API key",
	},
	{
		Name:        "secret_aws_sts_secret_key",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:aws_secret_access_key|secret_access_key|SecretAccessKey)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`,
		Description: "AWS STS secret access key in context",
	},
	{
		Name:        "secret_aws_sts_session_token",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:aws_session_token|aws_security_token|session_token|SessionToken|SecurityToken)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9/+=_-]{400,}["']?`,
		Description: "AWS STS session token",
	},
}

// CompiledSecretPatterns holds pre-compiled secret regex patterns.
var CompiledSecretPatterns []compiledPattern

func init() {
	CompiledSecretPatterns = compilePatterns(SecretsPatterns)
}

// DetectSecrets scans text for all secret patterns and returns matches.
func DetectSecrets(text string) []Match {
	return detectWithPatterns(text, CompiledSecretPatterns, string(CategorySecrets))
}
