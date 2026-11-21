// Package triage performs pure-Go behavioral capability detection, network IoC
// extraction, packer/entropy inspection, and Go garble obfuscation heuristics
// over analyzed ELF, PE, and Mach-O binaries.
package triage

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/aloneangel45/symforge/pkg/model"
)

// Severity classifies triage finding impact.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityInfo     Severity = "info"
)

// Finding is a structured behavioral capability, IoC, packer, or obfuscation finding.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence,omitempty"`
	MatchCount  int      `json:"match_count"`
}

// NetworkIoCs captures extracted URL and IPv4/IPv6 indicators from binary strings.
type NetworkIoCs struct {
	URLs        []string `json:"urls,omitempty"`
	PublicIPv4  []string `json:"public_ipv4,omitempty"`
	PrivateIPv4 []string `json:"private_ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
}

// ObfuscationReport summarizes packer signatures, high-entropy sections, and Go garble heuristics.
type ObfuscationReport struct {
	PackedLikely        bool                `json:"packed_likely"`
	UPXDetected         bool                `json:"upx_detected"`
	HighEntropySections []model.SectionInfo `json:"high_entropy_sections,omitempty"`
	GarbleLikely        bool                `json:"garble_likely"`
	GarbleConfidence    string              `json:"garble_confidence"`
	GarbleScore         int                 `json:"garble_score"`
	GarbleSignals       []string            `json:"garble_signals,omitempty"`
}

// ScanReport is the full behavioral and obfuscation triage report for a binary.
type ScanReport struct {
	Binary      model.BinaryInfo  `json:"binary"`
	RiskLevel   Severity          `json:"risk_level"`
	RiskScore   int               `json:"risk_score"`
	Summary     map[string]int    `json:"summary"`
	Findings    []Finding         `json:"findings,omitempty"`
	NetworkIoCs NetworkIoCs       `json:"network_iocs"`
	Obfuscation ObfuscationReport `json:"obfuscation"`
}

var (
	urlRe  = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp|tcp|udp|socks5?)://[^\s"'<>\\` + "`" + `]{4,180}`)
	ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	ipv6Re = regexp.MustCompile(`(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}`)
)

// Scan evaluates res for behavioral capabilities, network IoCs, secrets, packers, and Go garble obfuscation.
func Scan(res *model.AnalysisResult) (*ScanReport, error) {
	if res == nil {
		return nil, fmt.Errorf("cannot scan nil AnalysisResult")
	}

	report := &ScanReport{
		Binary:    res.Binary,
		RiskLevel: SeverityInfo,
		Summary: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"info":     0,
			"total":    0,
		},
	}

	// Build normalized searchable tables once.
	fnNames := make([]string, 0, len(res.Functions))
	for _, fn := range res.Functions {
		if fn.Demangled != "" {
			fnNames = append(fnNames, fn.Demangled)
		} else if fn.Name != "" {
			fnNames = append(fnNames, fn.Name)
		}
	}

	var findings []Finding

	// 1. Process / Execution capabilities
	if f := detectExecution(fnNames, res.Imports, res.Strings); f != nil {
		findings = append(findings, *f)
	}

	// 2. Network / C2 / TLS capabilities + IoC extraction
	report.NetworkIoCs = extractNetworkIoCs(res.Strings)
	if f := detectNetwork(fnNames, res.Imports, report.NetworkIoCs); f != nil {
		findings = append(findings, *f)
	}

	// 3. Memory / Injection capabilities
	if f := detectMemoryInjection(fnNames, res.Imports); f != nil {
		findings = append(findings, *f)
	}

	// 4. Anti-Debug / Anti-Analysis
	if f := detectAntiDebug(fnNames, res.Imports, res.Strings); f != nil {
		findings = append(findings, *f)
	}

	// 5. Persistence & Privilege Escalation
	if f := detectPersistence(res.Imports, res.Strings); f != nil {
		findings = append(findings, *f)
	}
	if f := detectPrivilege(fnNames, res.Imports, res.Strings); f != nil {
		findings = append(findings, *f)
	}

	// 6. Cryptography & Hardcoded Secret Candidates
	if f := detectCrypto(fnNames, res.Imports, res.Crypto); f != nil {
		findings = append(findings, *f)
	}
	if f := detectSecrets(res.Strings); f != nil {
		findings = append(findings, *f)
	}

	// 7. Packer, High-Entropy Sections & Go garble Obfuscation
	report.Obfuscation = detectObfuscation(res)
	if report.Obfuscation.UPXDetected || report.Obfuscation.PackedLikely {
		var ev []string
		if report.Obfuscation.UPXDetected {
			ev = append(ev, "UPX section/magic signature detected")
		}
		for _, s := range report.Obfuscation.HighEntropySections {
			ev = append(ev, fmt.Sprintf("section %s entropy=%.2f size=%d exec=%v", s.Name, s.Entropy, s.FileSize, s.Executable))
		}
		findings = append(findings, Finding{
			ID:          "OBF-PACK-001",
			Category:    "packer",
			Title:       "Packed or compressed executable detected",
			Severity:    SeverityHigh,
			Description: "Binary exhibits packer signatures (UPX) or high-entropy executable sections indicative of packing/encryption.",
			Evidence:    capEvidence(ev, 12),
			MatchCount:  maxInt(len(ev), 1),
		})
	} else if len(report.Obfuscation.HighEntropySections) > 0 {
		var ev []string
		for _, s := range report.Obfuscation.HighEntropySections {
			ev = append(ev, fmt.Sprintf("section %s entropy=%.2f size=%d exec=%v", s.Name, s.Entropy, s.FileSize, s.Executable))
		}
		findings = append(findings, Finding{
			ID:          "OBF-ENT-001",
			Category:    "obfuscation",
			Title:       "High-entropy section(s) (>= 7.0 bits/byte)",
			Severity:    SeverityMedium,
			Description: "One or more sections have Shannon entropy >= 7.0, suggesting embedded compressed, encrypted, or packed payloads.",
			Evidence:    capEvidence(ev, 12),
			MatchCount:  len(ev),
		})
	}

	if report.Obfuscation.GarbleLikely {
		sev := SeverityHigh
		if report.Obfuscation.GarbleConfidence == "medium" {
			sev = SeverityMedium
		}
		findings = append(findings, Finding{
			ID:          "OBF-GARBLE-001",
			Category:    "obfuscation",
			Title:       fmt.Sprintf("Go garble / symbol obfuscation likely (score %d/100, %s confidence)", report.Obfuscation.GarbleScore, report.Obfuscation.GarbleConfidence),
			Severity:    sev,
			Description: "Go binary shows stripped BuildInfo and/or randomized non-dictionary package/function identifiers consistent with garble obfuscation.",
			Evidence:    capEvidence(report.Obfuscation.GarbleSignals, 12),
			MatchCount:  len(report.Obfuscation.GarbleSignals),
		})
	}

	// Sort findings by severity descending, then ID.
	sort.Slice(findings, func(i, j int) bool {
		ri := severityRank(findings[i].Severity)
		rj := severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ID < findings[j].ID
	})

	report.Findings = findings

	score := 0
	for _, f := range findings {
		report.Summary[string(f.Severity)]++
		report.Summary["total"]++
		if severityRank(f.Severity) > severityRank(report.RiskLevel) {
			report.RiskLevel = f.Severity
		}
		switch f.Severity {
		case SeverityCritical:
			score += 35
		case SeverityHigh:
			score += 20
		case SeverityMedium:
			score += 10
		case SeverityInfo:
			score += 2
		}
	}
	if score > 100 {
		score = 100
	}
	report.RiskScore = score

	return report, nil
}

func detectExecution(fnNames []string, imports []model.ImportSymbol, strs []model.ExtractedString) *Finding {
	ev := newEvidenceSet()
	highRisk := false

	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		switch {
		case strings.HasPrefix(low, "os/exec.") || strings.Contains(low, "os/exec.("):
			ev.add("fn:" + fn)
		case strings.Contains(low, "syscall.exec") || strings.Contains(low, "syscall.forkexec") || strings.Contains(low, "syscall.startprocess"):
			ev.add("fn:" + fn)
		case strings.Contains(low, "std::process::command") || strings.Contains(low, "tokio::process::command"):
			ev.add("fn:" + fn)
		}
	}

	execAPIs := []string{
		"createprocess", "winexec", "shellexecute", "popen", "execve", "posix_spawn",
	}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		clean := strings.TrimLeft(strings.ToLower(imp.Name), "_")
		if clean == "system" || clean == "popen" {
			ev.add("import:" + formatImport(imp))
			highRisk = true
			continue
		}
		for _, api := range execAPIs {
			if strings.Contains(clean, api) {
				ev.add("import:" + formatImport(imp))
				if api == "winexec" || api == "createprocess" || api == "execve" {
					highRisk = true
				}
				break
			}
		}
	}

	for _, st := range strs {
		if st.Kind == model.StringCommand {
			ev.add("cmd:" + truncate(st.Value, 72))
		}
	}

	if ev.len() == 0 {
		return nil
	}
	sev := SeverityMedium
	if highRisk && ev.len() >= 2 {
		sev = SeverityHigh
	}
	return &Finding{
		ID:          "CAP-EXEC-001",
		Category:    "execution",
		Title:       "Process spawning / command execution capability",
		Severity:    sev,
		Description: "Binary references OS process creation APIs, Go/Rust process launchers, or shell command strings.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func extractNetworkIoCs(strs []model.ExtractedString) NetworkIoCs {
	urlSet := newEvidenceSet()
	pubV4 := newEvidenceSet()
	privV4 := newEvidenceSet()
	v6Set := newEvidenceSet()

	for _, st := range strs {
		val := st.Value
		if val == "" {
			continue
		}
		foundURL := false
		for _, u := range urlRe.FindAllString(val, 4) {
			u = strings.TrimRight(u, `),.;:]"'`)
			if strings.Contains(u, "://") && len(u) >= 8 {
				urlSet.add(truncate(u, 160))
				foundURL = true
			}
		}
		if !foundURL && st.Kind == model.StringURL && strings.Contains(val, "://") {
			urlSet.add(truncate(val, 160))
		}

		// IPv4 extraction with boundary checks against OIDs and version strings
		locs := ipv4Re.FindAllStringIndex(val, 8)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if start > 0 {
				prev := val[start-1]
				if prev == '.' || prev == 'v' || prev == 'V' || (prev >= '0' && prev <= '9') {
					continue
				}
			}
			if end < len(val) {
				next := val[end]
				if next == '.' || (next >= '0' && next <= '9') {
					continue
				}
			}
			cand := val[start:end]
			ip := net.ParseIP(cand)
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			// Exclude standard X.509 ASN.1 OIDs (2.5.4.* and 2.5.29.*) and subnet masks (255.255.*)
			if (ip4[0] == 2 && ip4[1] == 5 && (ip4[2] == 4 || ip4[2] == 29)) || (ip4[0] == 255 && ip4[1] == 255) {
				continue
			}
			if ip4.IsPrivate() || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() || ip4.IsUnspecified() || ip4[0] == 0 {
				privV4.add(cand)
			} else {
				pubV4.add(cand)
			}
		}

		// IPv6 extraction with identifier-boundary & group guards (prevents Rust "::aead" / "sha2::" false positives)
		if strings.Contains(val, ":") {
			v6Locs := ipv6Re.FindAllStringIndex(val, 6)
			for _, loc := range v6Locs {
				start, end := loc[0], loc[1]
				if start > 0 && isIdentChar(val[start-1]) {
					continue
				}
				if end < len(val) && isIdentChar(val[end]) {
					continue
				}
				cand := val[start:end]
				if !isPlausibleIPv6(cand) {
					continue
				}
				ip := net.ParseIP(cand)
				if ip != nil && ip.To4() == nil {
					v6Set.add(ip.String())
				}
			}
		}
	}

	return NetworkIoCs{
		URLs:        urlSet.list(50),
		PublicIPv4:  pubV4.list(50),
		PrivateIPv4: privV4.list(50),
		IPv6:        v6Set.list(30),
	}
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == ':'
}

func isPlausibleIPv6(cand string) bool {
	if len(cand) < 3 || cand == "::" || strings.HasPrefix(cand, ":::") || strings.HasSuffix(cand, ":::") {
		return false
	}
	if cand == "::1" {
		return true
	}
	nonEmpty := 0
	for _, part := range strings.Split(cand, ":") {
		if part != "" {
			nonEmpty++
		}
	}
	return nonEmpty >= 2 && strings.Count(cand, ":") >= 2
}

func detectNetwork(fnNames []string, imports []model.ImportSymbol, iocs NetworkIoCs) *Finding {
	ev := newEvidenceSet()

	netFnPatterns := []string{
		"net/http.", "crypto/tls.", "net.dial", "net.(*dialer)", "net.listen",
		"reqwest::", "tokio::net", "hyper::", "ureq::",
	}
	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		for _, pat := range netFnPatterns {
			if strings.Contains(low, pat) {
				ev.add("fn:" + fn)
				break
			}
		}
	}

	netAPIs := []string{
		"winhttpopen", "winhttpconnect", "internetopen", "internetconnect",
		"urldownloadtofile", "wsastartup", "wsaconnect", "curl_easy_",
	}
	exactNetAPIs := map[string]bool{
		"socket": true, "connect": true, "send": true, "recv": true, "getaddrinfo": true,
	}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		clean := strings.TrimLeft(strings.ToLower(imp.Name), "_")
		if exactNetAPIs[clean] {
			ev.add("import:" + formatImport(imp))
			continue
		}
		for _, api := range netAPIs {
			if strings.Contains(clean, api) {
				ev.add("import:" + formatImport(imp))
				break
			}
		}
	}

	for _, u := range iocs.URLs {
		ev.add("url:" + u)
	}
	for _, ip := range iocs.PublicIPv4 {
		ev.add("ip:" + ip)
	}

	if ev.len() == 0 {
		return nil
	}
	sev := SeverityInfo
	if len(iocs.PublicIPv4) > 0 || len(iocs.URLs) > 0 {
		sev = SeverityMedium
	}
	return &Finding{
		ID:          "CAP-NET-001",
		Category:    "network",
		Title:       "Network / HTTP / TLS communication & indicators",
		Severity:    sev,
		Description: "Binary contains network client/server APIs, TLS stacks, or embedded URL/IP indicators.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectMemoryInjection(fnNames []string, imports []model.ImportSymbol) *Finding {
	ev := newEvidenceSet()
	hasAlloc := false
	hasRemoteAlloc := false
	hasWrite := false
	hasRemoteThread := false
	hasThreadCtx := false

	checkName := func(prefix, raw string) {
		clean := strings.TrimLeft(strings.ToLower(raw), "_")
		switch {
		case strings.Contains(clean, "writeprocessmemory") || strings.Contains(clean, "ntwritevirtualmemory"):
			hasWrite = true
			ev.add(prefix + raw)
		case strings.Contains(clean, "createremotethread") || strings.Contains(clean, "ntcreatethreadex") || strings.Contains(clean, "queueuserapc"):
			hasRemoteThread = true
			ev.add(prefix + raw)
		case strings.Contains(clean, "setthreadcontext"):
			hasThreadCtx = true
			ev.add(prefix + raw)
		case strings.Contains(clean, "virtualallocex") || strings.Contains(clean, "ntallocatevirtualmemory") || strings.Contains(clean, "ntunmapviewofsection"):
			hasRemoteAlloc = true
			hasAlloc = true
			ev.add(prefix + raw)
		case clean == "virtualalloc" || clean == "virtualprotect" || clean == "virtualprotectex" || clean == "mprotect":
			hasAlloc = true
			ev.add(prefix + raw)
		}
	}

	for _, imp := range imports {
		if imp.Name != "" {
			checkName("import:", imp.Name)
		}
	}
	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		if strings.Contains(low, "writeprocessmemory") || strings.Contains(low, "createremotethread") || strings.Contains(low, "virtualallocex") || strings.Contains(low, "ntcreatethreadex") {
			checkName("fn:", fn)
		}
	}

	if ev.len() == 0 {
		return nil
	}

	sev := SeverityInfo
	title := "Virtual memory / thread context APIs"
	if (hasWrite && (hasRemoteThread || hasThreadCtx)) || (hasRemoteAlloc && hasWrite) || hasRemoteThread {
		sev = SeverityCritical
		title = "Process injection / remote memory manipulation APIs"
	} else if hasWrite || hasRemoteAlloc {
		sev = SeverityHigh
		title = "Cross-process memory manipulation API detected"
	} else if hasAlloc {
		sev = SeverityInfo
		title = "Executable memory allocation / protection APIs"
	}

	return &Finding{
		ID:          "CAP-MEM-001",
		Category:    "memory_injection",
		Title:       title,
		Severity:    sev,
		Description: "Binary imports or references virtual memory allocation, protection, or remote thread injection primitives.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectAntiDebug(fnNames []string, imports []model.ImportSymbol, strs []model.ExtractedString) *Finding {
	ev := newEvidenceSet()
	highSignal := false

	antiDebugAPIs := []string{
		"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
		"outputdebugstring",
	}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		clean := strings.TrimLeft(strings.ToLower(imp.Name), "_")
		if clean == "ptrace" {
			ev.add("import:" + formatImport(imp))
			highSignal = true
			continue
		}
		for _, api := range antiDebugAPIs {
			if strings.Contains(clean, api) {
				ev.add("import:" + formatImport(imp))
				if api != "outputdebugstring" {
					highSignal = true
				}
				break
			}
		}
	}

	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		if strings.Contains(low, "syscall.ptrace") || strings.Contains(low, "isdebuggerpresent") || strings.Contains(low, "checkremotedebuggerpresent") {
			ev.add("fn:" + fn)
			highSignal = true
		}
	}

	for _, st := range strs {
		low := strings.ToLower(st.Value)
		if strings.Contains(low, "/proc/self/status") || strings.Contains(low, "tracerpid") || strings.Contains(low, "pt_deny_attach") {
			ev.add("str:" + truncate(st.Value, 72))
			highSignal = true
		}
	}

	if ev.len() == 0 {
		return nil
	}
	sev := SeverityMedium
	if highSignal {
		sev = SeverityHigh
	}
	return &Finding{
		ID:          "CAP-ADBG-001",
		Category:    "anti_debug",
		Title:       "Anti-debugging / debugger detection indicators",
		Severity:    sev,
		Description: "Binary references ptrace, Windows debugger checks, or Linux /proc/self/status TracerPid inspection.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectPersistence(imports []model.ImportSymbol, strs []model.ExtractedString) *Finding {
	ev := newEvidenceSet()

	persistAPIs := []string{
		"regsetvalue", "regcreatekey", "createservice", "openscmanager", "startservice",
	}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		low := strings.ToLower(imp.Name)
		for _, api := range persistAPIs {
			if strings.Contains(low, api) {
				ev.add("import:" + formatImport(imp))
				break
			}
		}
	}

	persistStrs := []string{
		`currentversion\run`, `currentversion\runonce`, `/etc/systemd/system`,
		`/etc/cron`, `crontab`, `schtasks`, `launchagents`, `launchdaemons`,
		`systemctl enable`,
	}
	for _, st := range strs {
		low := strings.ToLower(st.Value)
		for _, pat := range persistStrs {
			if strings.Contains(low, pat) {
				ev.add("str:" + truncate(st.Value, 72))
				break
			}
		}
	}

	if ev.len() == 0 {
		return nil
	}
	return &Finding{
		ID:          "CAP-PERS-001",
		Category:    "persistence",
		Title:       "Persistence mechanism indicators (registry / service / cron / systemd)",
		Severity:    SeverityHigh,
		Description: "Binary references OS autostart locations, scheduled task tools, Windows registry/service APIs, or LaunchAgents.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectPrivilege(fnNames []string, imports []model.ImportSymbol, strs []model.ExtractedString) *Finding {
	ev := newEvidenceSet()

	privAPIs := []string{
		"adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue",
		"impersonateloggedonuser",
	}
	exactPriv := map[string]bool{"setuid": true, "setgid": true, "seteuid": true}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		clean := strings.TrimLeft(strings.ToLower(imp.Name), "_")
		if exactPriv[clean] {
			ev.add("import:" + formatImport(imp))
			continue
		}
		for _, api := range privAPIs {
			if strings.Contains(clean, api) {
				ev.add("import:" + formatImport(imp))
				break
			}
		}
	}
	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		if strings.Contains(low, "syscall.setuid") || strings.Contains(low, "syscall.setgid") {
			ev.add("fn:" + fn)
		}
	}
	for _, st := range strs {
		low := strings.ToLower(st.Value)
		if strings.Contains(low, "sedebugprivilege") || strings.Contains(low, "setcbprivilege") || strings.Contains(low, "/etc/sudoers") {
			ev.add("str:" + truncate(st.Value, 72))
		}
	}

	if ev.len() == 0 {
		return nil
	}
	return &Finding{
		ID:          "CAP-PRIV-001",
		Category:    "privilege",
		Title:       "Privilege / token manipulation indicators",
		Severity:    SeverityHigh,
		Description: "Binary references privilege escalation tokens, SeDebugPrivilege, or UID/GID modification APIs.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectCrypto(fnNames []string, imports []model.ImportSymbol, crypto []model.CryptoDetection) *Finding {
	ev := newEvidenceSet()
	for _, c := range crypto {
		ev.add(fmt.Sprintf("const:%s (%s @ 0x%x)", c.Name, c.Algorithm, c.Addr))
	}
	cryptoFnPats := []string{
		"crypto/aes.", "crypto/rsa.", "crypto/sha256.", "crypto/sha512.",
		"crypto/cipher.", "crypto/ecdsa.", "crypto/ed25519.", "chacha20",
		"aes::", "rsa::", "sha2::", "ring::aead",
	}
	for _, fn := range fnNames {
		low := strings.ToLower(fn)
		for _, pat := range cryptoFnPats {
			if strings.Contains(low, pat) {
				ev.add("fn:" + fn)
				break
			}
		}
	}
	cryptoAPIs := []string{
		"bcryptencrypt", "bcryptdecrypt", "cryptencrypt", "cryptdecrypt",
		"evp_encryptinit", "evp_decryptinit", "aes_set_encrypt_key",
	}
	for _, imp := range imports {
		if imp.Name == "" {
			continue
		}
		low := strings.ToLower(imp.Name)
		for _, api := range cryptoAPIs {
			if strings.Contains(low, api) {
				ev.add("import:" + formatImport(imp))
				break
			}
		}
	}
	if ev.len() == 0 {
		return nil
	}
	return &Finding{
		ID:          "CAP-CRYP-001",
		Category:    "crypto",
		Title:       "Cryptographic primitives / constants present",
		Severity:    SeverityInfo,
		Description: "Binary embeds cryptographic lookup tables or references AES/SHA-256/ChaCha20/RSA routines.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectSecrets(strs []model.ExtractedString) *Finding {
	ev := newEvidenceSet()
	for _, st := range strs {
		if st.Kind == model.StringSecretCandidate {
			ev.add(fmt.Sprintf("0x%x: %s", st.Addr, truncate(st.Value, 64)))
		}
	}
	if ev.len() == 0 {
		return nil
	}
	return &Finding{
		ID:          "CAP-SEC-001",
		Category:    "secrets",
		Title:       fmt.Sprintf("Hardcoded secret / key material candidate(s) (%d)", ev.len()),
		Severity:    SeverityHigh,
		Description: "Binary contains strings matching cloud API keys, private key PEM headers, tokens, or bearer credentials.",
		Evidence:    ev.list(15),
		MatchCount:  ev.len(),
	}
}

func detectObfuscation(res *model.AnalysisResult) ObfuscationReport {
	rep := ObfuscationReport{
		PackedLikely:     res.Binary.PackedLikely,
		GarbleConfidence: "none",
	}

	// UPX & High-Entropy Section Scan
	for _, s := range res.Sections {
		up := strings.ToUpper(s.Name)
		if strings.HasPrefix(up, "UPX") || strings.Contains(up, ".MPRESS") || strings.Contains(up, ".ASPACK") {
			rep.UPXDetected = true
			rep.PackedLikely = true
		}
		if s.Entropy >= 7.0 && s.FileSize >= 512 {
			rep.HighEntropySections = append(rep.HighEntropySections, s)
		}
	}
	// Only treat an embedded "UPX!" string as a UPX signature when the loader already flagged header packing
	// or high-entropy executable sections are present (avoids false positives on scanners containing "UPX!" literals).
	if res.Binary.PackedLikely {
		for _, st := range res.Strings {
			if strings.Contains(st.Value, "UPX!") {
				rep.UPXDetected = true
				break
			}
		}
	}

	// Go garble obfuscation heuristics
	isGo := (res.Go != nil && res.Go.Detected) || res.Binary.Language == model.LangGo || res.Binary.Language == model.LangGoRust
	if !isGo {
		return rep
	}

	score := 0
	var signals []string

	// Signal 1: Go detected with functions, yet BuildInfo is stripped/empty
	if res.Go != nil && len(res.Functions) >= 10 {
		if res.Go.MainModule == "" && len(res.Go.BuildSettings) == 0 && len(res.Dependencies) == 0 {
			score += 30
			signals = append(signals, "runtime.buildinfo stripped/empty despite recovered Go pclntab")
		}
		if res.Go.Version == "" {
			score += 15
			signals = append(signals, "Go toolchain version string missing/redacted")
		}
	}

	// Signal 2: Randomized base64-like / non-dictionary package & function identifiers
	var userOrDepFns []model.Function
	garbledFnCount := 0
	garbledFnSamples := make([]string, 0, 4)
	strippedSourceCount := 0
	hasMainMain := false

	for _, fn := range res.Functions {
		if fn.Name == "main.main" {
			hasMainMain = true
		}
		if fn.Category == model.CategoryUser || fn.Category == model.CategoryDependency {
			userOrDepFns = append(userOrDepFns, fn)
			if isGarbleIdentifier(fn.Package) || isGarbleFuncName(fn.Name) {
				garbledFnCount++
				if len(garbledFnSamples) < 4 {
					garbledFnSamples = append(garbledFnSamples, fn.Name)
				}
			}
			if fn.SourceFile == "" || isGarbleSourceFile(fn.SourceFile) {
				strippedSourceCount++
			}
		}
	}

	garbledPkgCount := 0
	garbledPkgSamples := make([]string, 0, 4)
	nonStdPkgCount := 0
	for _, p := range res.Packages {
		if p.Category == model.CategoryUser || p.Category == model.CategoryDependency {
			nonStdPkgCount++
			if isGarbleIdentifier(p.Name) {
				garbledPkgCount++
				if len(garbledPkgSamples) < 4 {
					garbledPkgSamples = append(garbledPkgSamples, p.Name)
				}
			}
		}
	}

	if len(userOrDepFns) >= 3 {
		ratio := float64(garbledFnCount) / float64(len(userOrDepFns))
		if ratio >= 0.35 && garbledFnCount >= 3 {
			score += 40
			signals = append(signals, fmt.Sprintf("randomized garble-like identifiers in %d/%d user/dep functions (e.g. %s)",
				garbledFnCount, len(userOrDepFns), strings.Join(garbledFnSamples, ", ")))
		}
	}
	if nonStdPkgCount >= 2 && float64(garbledPkgCount)/float64(nonStdPkgCount) >= 0.40 {
		score += 25
		signals = append(signals, fmt.Sprintf("anomalous obfuscated package names (%d/%d, e.g. %s)",
			garbledPkgCount, nonStdPkgCount, strings.Join(garbledPkgSamples, ", ")))
	}

	// Signal 3: Stripped or hash-obfuscated source filenames on user functions
	if len(userOrDepFns) >= 3 {
		srcRatio := float64(strippedSourceCount) / float64(len(userOrDepFns))
		if srcRatio >= 0.70 {
			score += 20
			signals = append(signals, fmt.Sprintf("source filenames stripped or obfuscated on %d/%d user/dep functions",
				strippedSourceCount, len(userOrDepFns)))
		}
	}

	// Signal 4: Missing main.main alongside other garble signals
	if !hasMainMain && len(res.Functions) >= 20 && score >= 20 {
		score += 15
		signals = append(signals, "main.main symbol absent or renamed in Go pclntab")
	}

	if score > 100 {
		score = 100
	}
	rep.GarbleScore = score
	rep.GarbleSignals = signals
	switch {
	case score >= 75:
		rep.GarbleLikely = true
		rep.GarbleConfidence = "high"
	case score >= 50:
		rep.GarbleLikely = true
		rep.GarbleConfidence = "medium"
	case score >= 25:
		rep.GarbleLikely = false
		rep.GarbleConfidence = "low"
	default:
		rep.GarbleLikely = false
		rep.GarbleConfidence = "none"
	}

	return rep
}

// isGarbleFuncName checks the package and leaf symbol portions of a Go symbol for garble-style random tokens.
func isGarbleFuncName(full string) bool {
	if full == "" || strings.HasPrefix(full, "go:") || strings.HasPrefix(full, "type:") {
		return false
	}
	// Split package.Func or pkg.(*Type).Method
	dot := strings.LastIndexByte(full, '.')
	if dot <= 0 || dot >= len(full)-1 {
		return isGarbleToken(full)
	}
	leaf := full[dot+1:]
	if leaf == "init" || leaf == "main" || strings.HasPrefix(leaf, "func") {
		return isGarbleIdentifier(full[:dot])
	}
	return isGarbleToken(leaf) || isGarbleIdentifier(full[:dot])
}

// isGarbleIdentifier evaluates a Go package path or single identifier for garble randomization.
func isGarbleIdentifier(pkg string) bool {
	if pkg == "" || pkg == "main" || pkg == "runtime" || pkg == "plugin" || pkg == "command-line-arguments" {
		return false
	}
	// Real Go module paths with known domain dots/slashes are rarely garbled unless segments themselves are random tokens.
	segs := strings.Split(pkg, "/")
	if len(segs) == 1 && !strings.Contains(pkg, ".") {
		return isGarbleToken(pkg)
	}
	randomSegs := 0
	for _, seg := range segs {
		if strings.Contains(seg, ".") {
			continue
		}
		if isGarbleToken(seg) {
			randomSegs++
		}
	}
	return randomSegs >= 2 || (len(segs) <= 2 && randomSegs >= 1 && !strings.Contains(segs[0], "."))
}

// isGarbleSourceFile returns true if a Go source filename looks hash-obfuscated (e.g. "x9Kp2mQ1.go" with no directory).
func isGarbleSourceFile(sf string) bool {
	if sf == "" || sf == "<autogenerated>" {
		return false
	}
	if strings.ContainsAny(sf, `/\`) {
		return false
	}
	base := strings.TrimSuffix(sf, ".go")
	return isGarbleToken(base)
}

// isGarbleToken detects short randomized base64-like Go identifiers produced by garble
// (e.g., "z8K2mN9q", "X4vB1pL0", "k9_mP2xZ") while rejecting normal camelCase/snake_case Go names.
func isGarbleToken(tok string) bool {
	tok = strings.TrimLeft(tok, "*()")
	if len(tok) < 6 || len(tok) > 22 {
		return false
	}
	var upper, lower, digits, underscores, vowels, caseSwitches int
	prevCase := 0 // 1=lower, 2=upper, 3=digit/other
	for i, r := range tok {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
		curCase := 3
		switch {
		case r >= 'a' && r <= 'z':
			lower++
			curCase = 1
			if isVowel(r) {
				vowels++
			}
		case r >= 'A' && r <= 'Z':
			upper++
			curCase = 2
			if isVowel(unicode.ToLower(r)) {
				vowels++
			}
		case r >= '0' && r <= '9':
			digits++
			curCase = 3
		case r == '_':
			underscores++
			curCase = 3
		}
		if i > 0 && curCase != prevCase {
			caseSwitches++
		}
		prevCase = curCase
	}

	// Normal Go identifiers almost never mix uppercase, lowercase, AND multiple interspersed digits with rapid case switching.
	if upper > 0 && lower > 0 && digits >= 2 && caseSwitches >= 4 {
		return true
	}
	// Base64-like mixed-case token with very high character entropy & high case-switch density & low vowels.
	ent := tokenEntropy(tok)
	letters := upper + lower
	if letters >= 6 && upper >= 2 && lower >= 2 && caseSwitches >= 4 && ent >= 2.9 {
		vowelRatio := float64(vowels) / float64(letters)
		if vowelRatio <= 0.25 || digits >= 1 {
			return true
		}
	}
	// Purely consonant/digit random hash with underscores
	if len(tok) >= 8 && digits >= 2 && vowels == 0 && (upper+lower) >= 4 && underscores <= 2 {
		return true
	}
	return false
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}

func tokenEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int, len(s))
	for _, r := range s {
		counts[r]++
	}
	inv := 1.0 / float64(len(s))
	var ent float64
	for _, c := range counts {
		p := float64(c) * inv
		ent -= p * math.Log2(p)
	}
	return ent
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

func formatImport(imp model.ImportSymbol) string {
	if imp.Library != "" && imp.Name != "" {
		return imp.Library + "!" + imp.Name
	}
	if imp.Name != "" {
		return imp.Name
	}
	return imp.Library
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	if len(s) > maxLen && maxLen > 3 {
		return s[:maxLen-3] + "..."
	}
	return s
}

func capEvidence(in []string, max int) []string {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type evidenceSet struct {
	seen map[string]struct{}
	vals []string
}

func newEvidenceSet() *evidenceSet {
	return &evidenceSet{seen: make(map[string]struct{})}
}

func (e *evidenceSet) add(v string) {
	if v == "" {
		return
	}
	if _, ok := e.seen[v]; ok {
		return
	}
	e.seen[v] = struct{}{}
	e.vals = append(e.vals, v)
}

func (e *evidenceSet) len() int {
	return len(e.vals)
}

func (e *evidenceSet) list(max int) []string {
	cp := append([]string(nil), e.vals...)
	sort.Strings(cp)
	if max > 0 && len(cp) > max {
		return cp[:max]
	}
	return cp
}
