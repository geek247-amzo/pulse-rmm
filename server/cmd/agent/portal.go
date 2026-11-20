package main

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
)

// This is a desktop link to a human-authenticated portal, not a privileged local
// service. No device token or fleet credential is written into the shortcut.
func installSupportShortcut(server string) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil {
		return
	}
	u.Scheme = "https"
	u.Path = "/support.html"
	u.RawQuery = ""
	u.Fragment = ""
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	switch runtime.GOOS {
	case "windows":
		desktop := filepath.Join(home, "Desktop")
		if info, err := os.Stat(desktop); err != nil || !info.IsDir() {
			return
		}
		_ = os.WriteFile(filepath.Join(desktop, "Pulse Support.url"), []byte("[InternetShortcut]\r\nURL="+u.String()+"\r\n"), 0600)
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		dir := filepath.Join(home, ".local", "share", "applications")
		if os.MkdirAll(dir, 0700) != nil {
			return
		}
		_ = os.WriteFile(filepath.Join(dir, "pulse-support.desktop"), []byte("[Desktop Entry]\nType=Link\nName=Pulse Support\nURL="+u.String()+"\nIcon=help-browser\n"), 0600)
	case "darwin":
		desktop := filepath.Join(home, "Desktop")
		if info, err := os.Stat(desktop); err != nil || !info.IsDir() {
			return
		}
		// A browser portal is available on macOS without opening a local control port.
		_ = os.WriteFile(filepath.Join(desktop, "Pulse Support.html"), []byte("<!doctype html><title>Pulse Support</title><p>Open your managed support portal:</p><a href=\""+u.String()+"\">Pulse Support</a>"), 0600)
	}
}
