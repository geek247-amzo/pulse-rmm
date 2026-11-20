package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

const MagicTrailer = "__PULSE_RMM_FOOTER__"

type EmbeddedConfig struct {
	ServerURL    string
	Token        string
	RustDeskHost string
	RustDeskKey  string
}

func readEmbeddedConfig() (*EmbeddedConfig, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(exePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	minSize := int64(len(MagicTrailer) + 4)
	if size < minSize {
		return nil, fmt.Errorf("file too small")
	}

	buf := make([]byte, len(MagicTrailer))
	if _, err := f.ReadAt(buf, size-int64(len(MagicTrailer))); err != nil {
		return nil, err
	}
	if string(buf) != MagicTrailer {
		return nil, fmt.Errorf("no magic trailer found")
	}

	lenBuf := make([]byte, 4)
	if _, err := f.ReadAt(lenBuf, size-int64(len(MagicTrailer))-4); err != nil {
		return nil, err
	}
	dataLen := binary.LittleEndian.Uint32(lenBuf)
	if int64(dataLen) > size-minSize || dataLen > 65536 {
		return nil, fmt.Errorf("invalid payload length")
	}

	payloadBuf := make([]byte, dataLen)
	if _, err := f.ReadAt(payloadBuf, size-minSize-int64(dataLen)); err != nil {
		return nil, err
	}

	parts := strings.Split(string(payloadBuf), "|")
	cfg := &EmbeddedConfig{}
	if len(parts) >= 1 {
		cfg.ServerURL = parts[0]
	}
	if len(parts) >= 2 {
		cfg.Token = parts[1]
	}
	if len(parts) >= 3 {
		cfg.RustDeskHost = parts[2]
	}
	if len(parts) >= 4 {
		cfg.RustDeskKey = parts[3]
	}
	return cfg, nil
}

func autoInstallSelf() {
	currExe, err := os.Executable()
	if err != nil {
		return
	}

	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			localAppData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		}
		targetDir := filepath.Join(localAppData, "PulseRMM")
		_ = os.MkdirAll(targetDir, 0755)
		targetExe := filepath.Join(targetDir, "rmm-agent.exe")

		if strings.EqualFold(currExe, targetExe) {
			return
		}

		if err := copyFile(currExe, targetExe); err == nil {
			// 1. Register HKCU Run key — no admin or UAC required, survives reboots
			_ = exec.Command("reg", "add",
				`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
				"/v", "PulseRMM",
				"/t", "REG_SZ",
				"/d", targetExe,
				"/f",
			).Run()

			// 2. Launch installed copy detached — GUI subsystem means zero console ever
			cmd := exec.Command(targetExe)
			setSysProcAttr(cmd)
			_ = cmd.Start()

			os.Exit(0)
		}

	case "linux":
		home, _ := os.UserHomeDir()
		targetDir := filepath.Join(home, ".local", "share", "pulsermm")
		_ = os.MkdirAll(targetDir, 0755)
		targetExe := filepath.Join(targetDir, "rmm-agent")

		if currExe == targetExe {
			return
		}

		if err := copyFile(currExe, targetExe); err == nil {
			_ = os.Chmod(targetExe, 0755)

			autostartDir := filepath.Join(home, ".config", "autostart")
			_ = os.MkdirAll(autostartDir, 0755)
			desktopFile := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=PulseRMM\nExec=%s -daemon\nHidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n", targetExe)
			_ = os.WriteFile(filepath.Join(autostartDir, "pulsermm.desktop"), []byte(desktopFile), 0644)

			cmd := exec.Command(targetExe, "-daemon")
			setSysProcAttr(cmd)
			_ = cmd.Start()
			os.Exit(0)
		}

	case "darwin":
		home, _ := os.UserHomeDir()
		targetDir := filepath.Join(home, "Library", "Application Support", "PulseRMM")
		_ = os.MkdirAll(targetDir, 0755)
		targetExe := filepath.Join(targetDir, "rmm-agent")

		if currExe == targetExe {
			return
		}

		if err := copyFile(currExe, targetExe); err == nil {
			_ = os.Chmod(targetExe, 0755)
			launchAgentsDir := filepath.Join(home, "Library", "LaunchAgents")
			_ = os.MkdirAll(launchAgentsDir, 0755)
			plistFile := filepath.Join(launchAgentsDir, "com.pulse.rmm.plist")
			plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pulse.rmm</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>-daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`, targetExe)
			_ = os.WriteFile(plistFile, []byte(plistContent), 0644)
			_ = exec.Command("launchctl", "load", plistFile).Run()

			cmd := exec.Command(targetExe, "-daemon")
			setSysProcAttr(cmd)
			_ = cmd.Start()
			os.Exit(0)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

type DeviceMetrics struct {
	DeviceID      string           `json:"device_id"`
	Hostname      string           `json:"hostname"`
	OS            string           `json:"os"`
	Platform      string           `json:"platform"`
	Arch          string           `json:"arch"`
	Uptime        uint64           `json:"uptime"`
	CPUPercent    float64          `json:"cpu_percent"`
	CPUCount      int              `json:"cpu_count"`
	CPUModel      string           `json:"cpu_model"`
	TotalRAM      uint64           `json:"total_ram"`
	UsedRAM       uint64           `json:"used_ram"`
	RAMPercent    float64          `json:"ram_percent"`
	TotalDisk     uint64           `json:"total_disk"`
	UsedDisk      uint64           `json:"used_disk"`
	DiskPercent   float64          `json:"disk_percent"`
	IPAddresses   []string         `json:"ip_addresses"`
	RustDeskSetup string           `json:"rustdesk_setup,omitempty"`
	SSHReady      *bool            `json:"ssh_ready,omitempty"`
	RustDeskID    string           `json:"rustdesk_id,omitempty"`
	Network       []NetworkMetric  `json:"network"`
	Processes     []ProcessMetric  `json:"processes"`
	Services      []ServiceMetric  `json:"services"`
	Security      []SecurityCheck  `json:"security_checks,omitempty"`
	Logs          []DeviceLogEntry `json:"logs,omitempty"`
	LogStatus     string           `json:"log_collection_status,omitempty"`
}

type DeviceLogEntry struct {
	ID         string    `json:"id"`
	RecordedAt time.Time `json:"recorded_at"`
	Level      string    `json:"level"`
	Source     string    `json:"source"`
	Message    string    `json:"message"`
}

type SecurityCheck struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Control   string    `json:"control"`
	Status    string    `json:"status"`
	Evidence  string    `json:"evidence"`
	CheckedAt time.Time `json:"checked_at"`
}

var securityCacheMu sync.Mutex
var securityCache []SecurityCheck
var securityCacheAt time.Time

type NetworkMetric struct {
	Name      string `json:"name"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
}
type ProcessMetric struct {
	PID  int32   `json:"pid"`
	Name string  `json:"name"`
	CPU  float64 `json:"cpu_percent"`
	RAM  uint64  `json:"memory_bytes"`
}
type ServiceMetric struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

var logCacheMu sync.Mutex
var logCacheAt time.Time
var logCache []DeviceLogEntry
var logCacheStatus string

func collectDeviceLogs() ([]DeviceLogEntry, string) {
	logCacheMu.Lock()
	defer logCacheMu.Unlock()
	if time.Since(logCacheAt) < time.Minute {
		return nil, logCacheStatus
	}
	logCacheAt = time.Now()
	logCache = nil
	logCacheStatus = "unsupported"
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("journalctl", "--since=-2min", "--priority=warning", "--output=json", "--no-pager", "-n", "40")
		data, err := cmd.CombinedOutput()
		if err != nil {
			detail := strings.ToLower(string(data) + " " + err.Error())
			if strings.Contains(detail, "permission denied") || strings.Contains(detail, "not permitted") {
				logCacheStatus = "permission_denied"
			} else {
				logCacheStatus = "unavailable"
			}
			return nil, logCacheStatus
		}
		logCacheStatus = "available"
		for _, line := range strings.Split(string(data), "\n") {
			var row map[string]interface{}
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			msg, _ := row["MESSAGE"].(string)
			if msg == "" {
				continue
			}
			source, _ := row["SYSLOG_IDENTIFIER"].(string)
			if source == "" {
				source, _ = row["_SYSTEMD_UNIT"].(string)
			}
			priority, _ := row["PRIORITY"].(string)
			level := "warning"
			if priority == "0" || priority == "1" || priority == "2" || priority == "3" {
				level = "error"
			}
			ts := time.Now().UTC()
			if micros, ok := row["__REALTIME_TIMESTAMP"].(string); ok {
				if n, e := strconv.ParseInt(micros, 10, 64); e == nil {
					ts = time.UnixMicro(n).UTC()
				}
			}
			if len(msg) > 1200 {
				msg = msg[:1200]
			}
			sum := sha256.Sum256([]byte(ts.Format(time.RFC3339Nano) + source + msg))
			logCache = append(logCache, DeviceLogEntry{ID: hex.EncodeToString(sum[:]), RecordedAt: ts, Level: level, Source: source, Message: msg})
		}
	case "windows":
		ps := `Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 40 -ErrorAction SilentlyContinue | Select-Object TimeCreated,ProviderName,LevelDisplayName,Message | ConvertTo-Json -Compress`
		data, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
		if err != nil {
			logCacheStatus = "unavailable"
			return nil, logCacheStatus
		}
		var rows []struct {
			TimeCreated                             time.Time
			ProviderName, LevelDisplayName, Message string
		}
		if json.Unmarshal(data, &rows) != nil {
			var one struct {
				TimeCreated                             time.Time
				ProviderName, LevelDisplayName, Message string
			}
			if json.Unmarshal(data, &one) == nil {
				rows = []struct {
					TimeCreated                             time.Time
					ProviderName, LevelDisplayName, Message string
				}{one}
			}
		}
		logCacheStatus = "available"
		for _, r := range rows {
			msg := r.Message
			if len(msg) > 1200 {
				msg = msg[:1200]
			}
			sum := sha256.Sum256([]byte(r.TimeCreated.UTC().Format(time.RFC3339Nano) + r.ProviderName + msg))
			level := "warning"
			if strings.Contains(strings.ToLower(r.LevelDisplayName), "error") || strings.Contains(strings.ToLower(r.LevelDisplayName), "critical") {
				level = "error"
			}
			logCache = append(logCache, DeviceLogEntry{ID: hex.EncodeToString(sum[:]), RecordedAt: r.TimeCreated.UTC(), Level: level, Source: r.ProviderName, Message: msg})
		}
	}
	return append([]DeviceLogEntry(nil), logCache...), logCacheStatus
}

func collectInventory() ([]NetworkMetric, []ProcessMetric, []ServiceMetric) {
	var networks []NetworkMetric
	if counters, err := gnet.IOCounters(true); err == nil {
		for _, n := range counters {
			networks = append(networks, NetworkMetric{Name: n.Name, BytesSent: n.BytesSent, BytesRecv: n.BytesRecv})
		}
	}
	var processes []ProcessMetric
	if list, err := process.Processes(); err == nil {
		for _, p := range list {
			name, err := p.Name()
			if err != nil {
				continue
			}
			cpuPct, _ := p.CPUPercent()
			memInfo, _ := p.MemoryInfo()
			var ram uint64
			if memInfo != nil {
				ram = memInfo.RSS
			}
			processes = append(processes, ProcessMetric{PID: p.Pid, Name: name, CPU: cpuPct, RAM: ram})
			if len(processes) == 50 {
				break
			}
		}
	}
	services := collectServices()
	return networks, processes, services
}

func collectServices() []ServiceMetric {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 -ExpandProperty Name")
	case "linux":
		command = exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager")
	case "darwin":
		command = exec.Command("launchctl", "list")
	default:
		return nil
	}
	data, err := command.Output()
	if err != nil {
		return nil
	}
	var result []ServiceMetric
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if runtime.GOOS == "linux" {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				line = fields[0]
			}
		}
		result = append(result, ServiceMetric{Name: line, Status: "running"})
		if len(result) == 30 {
			break
		}
	}
	return result
}

func securityCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func collectSecurity() []SecurityCheck {
	securityCacheMu.Lock()
	defer securityCacheMu.Unlock()
	if time.Since(securityCacheAt) < 5*time.Minute && len(securityCache) > 0 {
		return append([]SecurityCheck(nil), securityCache...)
	}
	checkedAt := time.Now().UTC()
	add := func(id, name, control, status, evidence string) SecurityCheck {
		return SecurityCheck{ID: id, Name: name, Control: control, Status: status, Evidence: evidence, CheckedAt: checkedAt}
	}
	checks := make([]SecurityCheck, 0, 6)
	if runtime.GOOS != "linux" {
		checks = append(checks,
			add("firewall", "Host firewall", "8.20 Network security", "unknown", "Automated evidence collection is currently available for Linux agents only"),
			add("disk_encryption", "System disk encryption", "8.24 Use of cryptography", "unknown", "Automated evidence collection is currently available for Linux agents only"),
			add("ssh_hardening", "SSH access hardening", "8.5 Secure authentication", "unknown", "Automated evidence collection is currently available for Linux agents only"),
			add("security_updates", "Automatic security updates", "8.8 Management of technical vulnerabilities", "unknown", "Automated evidence collection is currently available for Linux agents only"),
			add("system_logging", "System logging", "8.15 Logging", "unknown", "Automated evidence collection is currently available for Linux agents only"),
		)
		securityCache, securityCacheAt = checks, checkedAt
		return append([]SecurityCheck(nil), checks...)
	}

	// A host firewall is considered present only when a supported firewall
	// reports an active policy. Permission failures are unknown, never a fail.
	firewallRecorded := false
	if _, lookErr := exec.LookPath("ufw"); lookErr == nil {
		out, err := securityCommand("ufw", "status")
		if err == nil {
			if strings.Contains(strings.ToLower(out), "status: active") {
				checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "pass", "UFW reports active"))
			} else {
				checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "fail", "UFW reports inactive"))
			}
			firewallRecorded = true
		} else if strings.Contains(strings.ToLower(out), "permission") || strings.Contains(strings.ToLower(out), "root") {
			checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "unknown", "Firewall status requires elevated privileges"))
			firewallRecorded = true
		}
	}
	if !firewallRecorded {
		if _, lookErr := exec.LookPath("systemctl"); lookErr == nil {
			out, err := securityCommand("systemctl", "is-active", "firewalld.service")
			if err == nil && strings.TrimSpace(out) == "active" {
				checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "pass", "firewalld is active"))
				firewallRecorded = true
			}
		}
	}
	if !firewallRecorded {
		if _, lookErr := exec.LookPath("nft"); lookErr == nil {
			out, err := securityCommand("nft", "list", "ruleset")
			if err == nil {
				if strings.TrimSpace(out) != "" {
					checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "pass", "nftables ruleset is present"))
				} else {
					checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "fail", "nftables has no configured rules"))
				}
				firewallRecorded = true
			} else if strings.Contains(strings.ToLower(out), "permission") || strings.Contains(strings.ToLower(out), "operation not permitted") {
				checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "unknown", "Firewall rules require elevated privileges to inspect"))
				firewallRecorded = true
			}
		}
	}
	if !firewallRecorded {
		checks = append(checks, add("firewall", "Host firewall", "8.20 Network security", "unknown", "Could not inspect a supported firewall without elevated privileges"))
	}

	rootSource, rootErr := securityCommand("findmnt", "-n", "-o", "SOURCE", "/")
	if rootErr == nil && strings.HasPrefix(rootSource, "/dev/") {
		out, err := securityCommand("lsblk", "-s", "-n", "-o", "TYPE", rootSource)
		if err == nil && strings.Contains("\n"+out+"\n", "\ncrypt\n") {
			checks = append(checks, add("disk_encryption", "System disk encryption", "8.24 Use of cryptography", "pass", "Root filesystem is backed by a device-mapper crypt layer"))
		} else if err == nil {
			checks = append(checks, add("disk_encryption", "System disk encryption", "8.24 Use of cryptography", "fail", "No crypt layer was found in the root filesystem device chain"))
		} else {
			checks = append(checks, add("disk_encryption", "System disk encryption", "8.24 Use of cryptography", "unknown", "Could not inspect the root filesystem device chain"))
		}
	} else {
		checks = append(checks, add("disk_encryption", "System disk encryption", "8.24 Use of cryptography", "unknown", "Could not identify the root filesystem block device"))
	}

	sshActive := false
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if out, err := securityCommand("systemctl", "is-active", unit); err == nil && out == "active" {
			sshActive = true
			break
		}
	}
	if !sshActive {
		checks = append(checks, add("ssh_hardening", "SSH access hardening", "8.5 Secure authentication", "pass", "No active SSH service was detected"))
	} else if out, err := securityCommand("sshd", "-T"); err == nil {
		settings := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(strings.ToLower(line))
			if len(fields) == 2 {
				settings[fields[0]] = fields[1]
			}
		}
		rootLogin, passwordAuth := settings["permitrootlogin"], settings["passwordauthentication"]
		if rootLogin == "no" && passwordAuth == "no" {
			checks = append(checks, add("ssh_hardening", "SSH access hardening", "8.5 Secure authentication", "pass", "Root login and SSH password authentication are disabled"))
		} else {
			checks = append(checks, add("ssh_hardening", "SSH access hardening", "8.5 Secure authentication", "fail", fmt.Sprintf("sshd effective settings: PermitRootLogin=%s, PasswordAuthentication=%s", rootLogin, passwordAuth)))
		}
	} else {
		checks = append(checks, add("ssh_hardening", "SSH access hardening", "8.5 Secure authentication", "unknown", "SSH is active but effective sshd configuration could not be read"))
	}

	if out, err := securityCommand("systemctl", "is-active", "systemd-journald.service"); err == nil && out == "active" {
		checks = append(checks, add("system_logging", "System logging", "8.15 Logging", "pass", "systemd-journald is active"))
	} else {
		checks = append(checks, add("system_logging", "System logging", "8.15 Logging", "unknown", "systemd-journald status could not be confirmed"))
	}

	if out, err := securityCommand("apt-config", "dump"); err == nil && strings.Contains(out, `APT::Periodic::Unattended-Upgrade "1";`) {
		checks = append(checks, add("security_updates", "Automatic security updates", "8.8 Management of technical vulnerabilities", "pass", "APT unattended security upgrades are enabled"))
	} else if _, err := exec.LookPath("apt-config"); err == nil {
		checks = append(checks, add("security_updates", "Automatic security updates", "8.8 Management of technical vulnerabilities", "fail", "APT unattended security upgrades are not enabled"))
	} else {
		checks = append(checks, add("security_updates", "Automatic security updates", "8.8 Management of technical vulnerabilities", "unknown", "No supported package update configuration was detected"))
	}

	securityCache, securityCacheAt = checks, checkedAt
	return append([]SecurityCheck(nil), checks...)
}

func getDeviceID() string {
	hInfo, err := host.Info()
	if err == nil && hInfo.HostID != "" {
		hash := sha256.Sum256([]byte(hInfo.HostID))
		return hex.EncodeToString(hash[:])[:16]
	}
	hostname, _ := os.Hostname()
	hash := sha256.Sum256([]byte(hostname + runtime.GOOS + runtime.GOARCH))
	return hex.EncodeToString(hash[:])[:16]
}

func getIPAddresses() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, i := range ifaces {
		if (i.Flags&net.FlagUp == 0) || (i.Flags&net.FlagLoopback != 0) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips
}

func detectRustDeskID() string {
	var paths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		paths = append(paths,
			filepath.Join(appdata, "RustDesk", "config", "RustDesk2.toml"),
			filepath.Join(appdata, "RustDesk", "config", "RustDesk.toml"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "RustDesk", "config", "RustDesk2.toml"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "RustDesk", "config", "RustDesk.toml"),
			filepath.Join(os.Getenv("PROGRAMDATA"), "RustDesk", "config", "RustDesk2.toml"),
			"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\\config\\RustDesk2.toml",
			"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\\config\\RustDesk.toml",
		)
	case "linux":
		paths = append(paths,
			filepath.Join(home, ".config", "rustdesk", "RustDesk2.toml"),
			filepath.Join(home, ".config", "rustdesk", "RustDesk.toml"),
			"/root/.config/rustdesk/RustDesk2.toml",
			"/etc/rustdesk/RustDesk2.toml",
		)
	case "darwin":
		paths = append(paths,
			filepath.Join(home, "Library", "Preferences", "com.carriez.RustDesk", "RustDesk2.toml"),
		)
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "id = ") || strings.HasPrefix(line, "id=") || strings.HasPrefix(line, " rustdesk_id =") {
					parts := strings.Split(line, "=")
					if len(parts) >= 2 {
						id := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
						if id != "" {
							return id
						}
					}
				}
				if strings.Contains(strings.ToLower(line), "rustdesk_id") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						id := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
						if id != "" {
							return id
						}
					}
				}
			}
		}
	}
	return ""
}

func collectMetrics() (*DeviceMetrics, error) {
	hInfo, _ := host.Info()
	vMem, _ := mem.VirtualMemory()
	cpuPercents, _ := cpu.Percent(time.Second, false)
	cpuInfo, _ := cpu.Info()

	var cpuPct float64
	if len(cpuPercents) > 0 {
		cpuPct = cpuPercents[0]
	}

	cpuModel := "Unknown"
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
	}

	rootDiskPath := "/"
	if runtime.GOOS == "windows" {
		rootDiskPath = "C:\\"
	}
	dUsage, _ := disk.Usage(rootDiskPath)

	var totalDisk, usedDisk uint64
	var diskPct float64
	if dUsage != nil {
		totalDisk = dUsage.Total
		usedDisk = dUsage.Used
		diskPct = dUsage.UsedPercent
	}

	hostname, _ := os.Hostname()
	networks, processes, services := collectInventory()
	deviceLogs, logStatus := collectDeviceLogs()

	m := &DeviceMetrics{
		DeviceID:      getDeviceID(),
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Platform:      fmt.Sprintf("%s %s", hInfo.Platform, hInfo.PlatformVersion),
		Arch:          runtime.GOARCH,
		Uptime:        hInfo.Uptime,
		CPUPercent:    cpuPct,
		CPUCount:      runtime.NumCPU(),
		CPUModel:      cpuModel,
		TotalRAM:      vMem.Total,
		UsedRAM:       vMem.Used,
		RAMPercent:    vMem.UsedPercent,
		TotalDisk:     totalDisk,
		UsedDisk:      usedDisk,
		DiskPercent:   diskPct,
		IPAddresses:   getIPAddresses(),
		RustDeskID:    portalRustDeskID(),
		RustDeskSetup: rustDeskStatus(), SSHReady: localSSHReady(),
		Network: networks, Processes: processes, Services: services,
		Security: collectSecurity(),
		Logs:     deviceLogs, LogStatus: logStatus,
	}
	return m, nil
}

type boundedCommandOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *boundedCommandOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	left := (256 << 10) - o.buf.Len()
	if left > 0 {
		n := len(data)
		if n > left {
			n = left
		}
		_, _ = o.buf.Write(data[:n])
	}
	return len(data), nil
}
func executeCommand(cmdStr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", cmdStr)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	setSysProcAttr(cmd)
	cmd.WaitDelay = 2 * time.Second
	output := &boundedCommandOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return output.buf.String(), err
}

func getPersistentTokenPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "pulse-rmm-token.txt")
}

func loadOrSaveDeviceKey(initialKey string) string {
	path := getPersistentTokenPath()
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		return strings.TrimSpace(string(data))
	}
	if initialKey != "" {
		_ = os.WriteFile(path, []byte(initialKey), 0600)
		return initialKey
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	key := hex.EncodeToString(buf)
	_ = os.WriteFile(path, []byte(key), 0600)
	return key
}

func main() {
	embedded, _ := readEmbeddedConfig()

	defaultServer := "wss://localhost/ws/agent"
	defaultSecret := ""
	rdHost := ""
	rdKey := ""

	if embedded != nil {
		if embedded.ServerURL != "" {
			defaultServer = embedded.ServerURL
		}
		if embedded.Token != "" {
			defaultSecret = embedded.Token
		}
		if embedded.RustDeskHost != "" {
			rdHost = embedded.RustDeskHost
		}
		if embedded.RustDeskKey != "" {
			rdKey = embedded.RustDeskKey
		}
	}

	serverURL := flag.String("server", defaultServer, "Server WS endpoint")
	secret := flag.String("secret", defaultSecret, "Agent token")
	interval := flag.Int("interval", 5, "Polling interval in seconds")
	// Unix self-install relaunches with this marker so the child can be
	// distinguished in process listings. Accept it even though installation
	// location checks already prevent another copy from being spawned.
	_ = flag.Bool("daemon", false, "Run the installed background agent")
	flag.Parse()

	// Always auto-install on first run; autoInstallSelf() is a no-op if already installed
	autoInstallSelf()

	// Persist token so the device keeps working even if re-run
	activeSecret := loadOrSaveDeviceKey(*secret)

	if rdHost != "" && rdKey != "" {
		go setupRustDesk(rdHost, rdKey)
	}
	installSupportShortcut(*serverURL)

	log.Printf("PulseRMM Background Service running. Target: %s", *serverURL)

	for {
		u, err := url.Parse(*serverURL)
		if err != nil {
			log.Fatalf("Invalid server URL: %v", err)
		}

		// Credentials are headers only: never place agent secrets in logged URLs.
		u.RawQuery = ""

		header := http.Header{}
		header.Set("X-Agent-Secret", activeSecret)
		header.Set("X-Agent-Token", activeSecret)

		conn, resp, err := websocket.DefaultDialer.Dial(u.String(), header)
		if err != nil {
			msg := fmt.Sprintf("%v", err)
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				body, _ := io.ReadAll(resp.Body)
				msg = fmt.Sprintf("Server rejected token: %s", string(body))
			}
			log.Printf("Connection error: %s. Reconnecting in 5 seconds...", msg)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Println("Connected successfully to RMM Server!")

		var writeMu sync.Mutex
		// Incoming commands handler
		go func(c *websocket.Conn) {
			for {
				var msg map[string]interface{}
				if err := c.ReadJSON(&msg); err != nil {
					return
				}
				if msg["type"] == "exec" {
					command, _ := msg["command"].(string)
					jobID, _ := msg["job_id"].(string)
					output, err := executeCommand(command)
					errStr := ""
					if err != nil {
						errStr = err.Error()
					}
					writeMu.Lock()
					_ = c.WriteJSON(map[string]interface{}{
						"type": "command_result",
						"data": map[string]interface{}{
							"job_id": jobID,
							"output": output,
							"error":  errStr,
						},
					})
					writeMu.Unlock()
				}
			}
		}(conn)

		// Heartbeat and metrics sender loop
		ticker := time.NewTicker(time.Duration(*interval) * time.Second)
		connected := true
		for connected {
			select {
			case <-ticker.C:
				stats, err := collectMetrics()
				if err != nil {
					continue
				}
				payload := map[string]interface{}{
					"type": "metrics",
					"data": stats,
				}
				writeMu.Lock()
				writeErr := conn.WriteJSON(payload)
				writeMu.Unlock()
				if err := writeErr; err != nil {
					log.Printf("Write error: %v. Reconnecting...", err)
					conn.Close()
					connected = false
				}
			}
		}
		ticker.Stop()
		time.Sleep(3 * time.Second)
	}
}
