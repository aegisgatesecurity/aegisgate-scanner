// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Evasion Technique Detection Patterns
// =========================================================================
//
// Patterns for detecting security evasion technique requests in AI prompts.
// Ported from Platform v4.7.0 scanner patterns (Phase 2 expansion).
// =========================================================================

package detectors

// EvasionPatterns defines security evasion technique detection patterns.
var EvasionPatterns = []PatternDef{
	{
		Name:        "evasion_log_purge",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:purge|clear|delete|wipe|tamper|modify|alter).{0,20}(?:SIEM|audit|security|event|unified|bash\s+history|system).{0,10}(?:logs?|trails?|records?|history)\b`,
		Description: "Security log purge/tampering request",
	},
	{
		Name:        "evasion_disable_monitor",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:disable|turn\s+off|deactivate|stop|kill|terminate).{0,20}(?:Sysmon|AMSI|EDR|XDR|Windows\s+Defender|Windows\s+Security\s+Center|antivirus|anti-?virus|AppLocker|Gatekeeper|monitoring|detection)\b`,
		Description: "Security monitoring disable request",
	},
	{
		Name:        "evasion_hide_process",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:hide|conceal|mask|camouflage).{0,20}(?:process(?:es)?|from\s+ps|from\s+task\s+manager|from\s+top|running\s+process)\b`,
		Description: "Process hiding/evasion request",
	},
	{
		Name:        "evasion_lolbin",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:live\s+off\s+the\s+land|LOLBin|LOLBins|living-?off-?the-?land)\b`,
		Description: "Living off the land binary abuse",
	},
	{
		Name:        "evasion_process_hollowing",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:process\s+hollowing|process\s+doppelganging|process\s+herpaderping|inject\s+code\s+into\s+(?:legitimate|signed|trusted)\s+process)\b`,
		Description: "Process injection/hollowing for evasion",
	},
	{
		Name:        "evasion_memory_scan",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:evade|bypass|escape).{0,20}(?:memory\s+scanning|memory\s+scanner|memory\s+analysis|YARA|EDR\s+memory|hooking)\b`,
		Description: "Memory scanning evasion",
	},
	{
		Name:        "evasion_dll_sideloading",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:DLL\s+side-?loading|DLL\s+hijacking|DLL\s+injection|DLL\s+proxying)\b`,
		Description: "DLL side-loading/hijacking for evasion",
	},
	{
		Name:        "evasion_ads",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:alternate\s+data\s+streams?|ADS\b).{0,30}(?:hide|conceal|store|embed|smuggle)\b`,
		Description: "Alternate data streams for file hiding",
	},
	{
		Name:        "evasion_network_evasion",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:evade|bypass|circumvent).{0,20}(?:network\s+(?:detection|IDS|IPS|NDR|monitoring)|firewall|proxy\s+detection)\b`,
		Description: "Network detection evasion",
	},
	{
		Name:        "evasion_rootkit_stealth",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:rootkit\b.{0,30}(?:technique|stealth|hide|persist)|use\s+rootkit\s+(?:techniques?|methods?))\b`,
		Description: "Rootkit stealth techniques",
	},
	{
		Name:        "evasion_uac_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:bypass\s+(?:UAC|User\s+Account\s+Control)|UAC\s+bypass)\b`,
		Description: "UAC bypass technique",
	},
	{
		Name:        "evasion_sandbox",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:bypass|evade|escape|detect).{0,20}(?:sandbox|sand-?box|analysis\s+environment|virtual\s+(?:machine|environment)|VM\s+detection)\b`,
		Description: "Sandbox/VM detection bypass",
	},
}

// CompiledEvasionPatterns holds pre-compiled evasion regex patterns.
var CompiledEvasionPatterns []compiledPattern

func init() {
	CompiledEvasionPatterns = compilePatterns(EvasionPatterns)
}

// DetectEvasion scans text for all evasion patterns and returns matches.
func DetectEvasion(text string) []Match {
	return detectWithPatterns(text, CompiledEvasionPatterns, string(CategoryEvasion))
}
