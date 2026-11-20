package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var supportStatus = struct {
	sync.RWMutex
	text string
	id   string
}{text: "Preparing RustDesk"}

var rustDeskIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)

func portalRustDeskID() string {
	supportStatus.RLock()
	id := supportStatus.id
	supportStatus.RUnlock()
	if id != "" {
		return id
	}
	id = detectRustDeskID()
	if rustDeskIDPattern.MatchString(id) {
		return id
	}
	return ""
}

func rustDeskStatus() string {
	supportStatus.RLock()
	defer supportStatus.RUnlock()
	return supportStatus.text
}

func setupRustDesk(host, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	status := installAndConfigureRustDesk(ctx, host, key)
	supportStatus.Lock()
	supportStatus.text = status
	supportStatus.Unlock()
	log.Print(status)
}

type releaseAsset struct{ suffix, digest string }

var rustDeskAssets = map[string]releaseAsset{
	"windows/amd64": {"-x86_64.exe", "523ba0efbf62a21739961b62c7daaffb44d3da86139c546b364fd4e1333ed249"},
	"linux/amd64":   {"-x86_64.deb", "81096d2f65fd43352540c351bca15bb0712a2a6f9efa4c95e9fff25cb97b3b81"},
	"linux/arm64":   {"-aarch64.deb", "fa85e8d3ccd45e2e303c2d1359af5dc51aa93d880e39ba47c9b04bfabd82ae19"},
	"darwin/amd64":  {"-x86_64.dmg", "74d06e6b2e273a128e8d36313e30d47db2063f453a4235ed4d9e5cdfdf9be538"},
	"darwin/arm64":  {"-aarch64.dmg", "e6d30fa1633d772c48935907c208ca4e555a856fb2038af3aaa87a327c29360b"},
}

func downloadRustDesk(ctx context.Context, dir string, asset releaseAsset) (string, error) {
	const version = "1.5.3"
	name := "rustdesk-" + version + asset.suffix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/rustdesk/rustdesk/releases/download/"+version+"/"+name, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, 100<<20))
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if hex.EncodeToString(hash.Sum(nil)) != asset.digest {
		return "", fmt.Errorf("installer checksum mismatch")
	}
	return path, nil
}

func runSupport(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	setSysProcAttr(cmd)
	data, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(data)), err
}

func rustDeskBinary() string {
	if path, err := exec.LookPath("rustdesk"); err == nil {
		return path
	}
	paths := []string{"/usr/bin/rustdesk", "/Applications/RustDesk.app/Contents/MacOS/RustDesk"}
	if runtime.GOOS == "windows" {
		paths = []string{filepath.Join(os.Getenv("ProgramFiles"), "RustDesk", "rustdesk.exe")}
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func installAndConfigureRustDesk(ctx context.Context, host, key string) string {
	asset, ok := rustDeskAssets[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "RustDesk installer unavailable for this OS or architecture"
	}
	if runtime.GOOS == "windows" {
		if _, err := runSupport(ctx, "fltmc.exe"); err != nil {
			return "Run deployment from an elevated Windows session to set up RustDesk"
		}
	} else if os.Geteuid() != 0 {
		if _, err := runSupport(ctx, "sudo", "-n", "true"); err != nil {
			return "RustDesk setup needs local administrator access"
		}
	}
	admin := func(name string, args ...string) (string, error) {
		if runtime.GOOS != "windows" && os.Geteuid() != 0 {
			return runSupport(ctx, "sudo", append([]string{"-n", name}, args...)...)
		}
		return runSupport(ctx, name, args...)
	}
	binary := rustDeskBinary()
	if binary == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "RustDesk cache directory unavailable"
		}
		if err = os.MkdirAll(cache, 0700); err != nil {
			return "Cannot create RustDesk cache directory"
		}
		stage, err := os.MkdirTemp(cache, "pulsermm-rustdesk-")
		if err != nil {
			return "Cannot create RustDesk installer directory"
		}
		defer os.RemoveAll(stage)
		path, err := downloadRustDesk(ctx, stage, asset)
		if err != nil {
			return "RustDesk installer download failed: " + err.Error()
		}
		switch runtime.GOOS {
		case "windows":
			if _, err = runSupport(ctx, path, "--silent-install"); err != nil {
				return "RustDesk silent install failed"
			}
		case "linux":
			apt, err := exec.LookPath("apt-get")
			if err != nil {
				return "Automatic RustDesk installation requires Debian or Ubuntu on Linux"
			}
			if _, err = admin(apt, "-y", "-o", "Dpkg::Options::=--force-confold", "install", path); err != nil {
				return "RustDesk package installation failed"
			}
		case "darwin":
			mount := filepath.Join(stage, "mount")
			if _, err = runSupport(ctx, "hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mount, path); err != nil {
				return "RustDesk disk image could not be mounted"
			}
			defer func() {
				detach, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_, _ = runSupport(detach, "hdiutil", "detach", mount)
			}()
			if _, err = admin("/usr/bin/ditto", filepath.Join(mount, "RustDesk.app"), "/Applications/RustDesk.app"); err != nil {
				return "RustDesk app installation failed"
			}
		}
		binary = rustDeskBinary()
	}
	if binary == "" {
		return "RustDesk executable unavailable after installation"
	}
	if runtime.GOOS == "linux" {
		if _, err := admin("/usr/bin/systemctl", "enable", "--now", "rustdesk.service"); err != nil {
			return "RustDesk service could not be started"
		}
	}
	if runtime.GOOS == "darwin" {
		if _, err := admin(binary, "--install-service"); err != nil {
			return "RustDesk service setup needs macOS approval"
		}
	}
	for _, option := range [][2]string{{"key", key}, {"custom-rendezvous-server", host}, {"relay-server", ""}} {
		if _, err := admin(binary, "--option", option[0], option[1]); err != nil {
			return "RustDesk server configuration failed"
		}
	}
	reported, err := admin(binary, "--option", "custom-rendezvous-server")
	reportedKey, keyErr := admin(binary, "--option", "key")
	if err != nil || keyErr != nil || reported != host || reportedKey != key {
		return "Could not confirm RustDesk server configuration"
	}
	if id, err := admin(binary, "--get-id"); err == nil && rustDeskIDPattern.MatchString(id) {
		supportStatus.Lock()
		supportStatus.id = id
		supportStatus.Unlock()
	}
	if id := portalRustDeskID(); id != "" {
		return "RustDesk configured. Waiting for or using endpoint session approval"
	}
	return "RustDesk configured. Waiting for a device ID"
}

func localSSHReady() *bool {
	ready := false
	for _, address := range []string{"127.0.0.1", "::1"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, "22"), 350*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		banner, _ := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
		conn.Close()
		if strings.HasPrefix(banner, "SSH-") {
			ready = true
			break
		}
	}
	return &ready
}
