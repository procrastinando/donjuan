package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed index.html
var content embed.FS

var (
	appData AppData
	dataMu  sync.Mutex
)

func loadData() {
	dataMu.Lock()
	defer dataMu.Unlock()
	
	// Set Defaults
	appData.Port = 8080
	appData.Settings.FakeIP = true
	appData.Settings.TUN = true
	appData.Settings.Sniffing = true
	appData.Settings.LocalNetwork = true

b, err := os.ReadFile("donjuan-data/data.json")
		if err == nil {
		json.Unmarshal(b, &appData)
	}
	saveLogs = appData.Settings.SaveLogs
}

func saveDataFile() {
	dataMu.Lock()
	defer dataMu.Unlock()
	b, _ := json.MarshalIndent(appData, "", "  ")
	os.WriteFile("donjuan-data/data.json", b, 0644)
}

func detectOS() string {
	switch runtime.GOOS {
	case "windows":
		if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
			s := strings.TrimSpace(string(out))
			s = strings.TrimPrefix(s, "Microsoft Windows [Version ")
			s = strings.TrimSuffix(s, "]")
			if s != "" {
				return "windows " + s
			}
		}
		return "windows"
default:
		if b, err := os.ReadFile("/etc/openwrt_release"); err == nil {
			s := string(b)
			var ver, arch string
			for _, line := range strings.Split(s, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "DISTRIB_VERSION=") {
					v := strings.TrimPrefix(line, "DISTRIB_VERSION=")
					v = strings.Trim(v, "'\"")
					ver = v
				}
				if strings.HasPrefix(line, "DISTRIB_ARCH=") {
					a := strings.TrimPrefix(line, "DISTRIB_ARCH=")
					a = strings.Trim(a, "'\"")
					arch = a
				}
			}
			if ver != "" {
				r := "openwrt" + ver
				if arch != "" {
					r += " " + arch
				}
				return r
			}
		}
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			s := string(b)
			var name, ver string
			for _, line := range strings.Split(s, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ID=") {
					name = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				}
				if strings.HasPrefix(line, "VERSION_ID=") {
					ver = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
				}
			}
			if name != "" {
				r := name
				if ver != "" {
					r += ver
				}
				return r
			}
		}
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			if b, err := os.ReadFile("/etc/debian_version"); err == nil {
				return "debian" + strings.TrimSpace(string(b))
			}
			return "debian"
		}
		if _, err := os.Stat("/etc/redhat-release"); err == nil {
			if b, err := os.ReadFile("/etc/redhat-release"); err == nil {
				return strings.TrimSpace(string(b))
			}
		}
		return runtime.GOOS
	}
}

func main() {
	loadData()
	if appData.Port == 0 {
		appData.Port = 8080
	}

	if os.Getenv("DONJUAN_DAEMONIZED") != "1" {
		os.MkdirAll("donjuan-data", 0755)
		execPath, _ := os.Executable()
		cmd := exec.Command(execPath, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "DONJUAN_DAEMONIZED=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Start()
		fmt.Printf("DonJuan VPN started in background (PID %d)\n", cmd.Process.Pid)
		os.Exit(0)
	}

	logFile, _ := os.OpenFile("donjuan-data/donjuan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if logFile != nil {
		log.SetOutput(logFile)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := content.ReadFile("index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		configData, _ := os.ReadFile("donjuan-data/config.json")
		configJSON := "{}"
		if len(configData) > 0 {
			configJSON = string(configData)
		}
		html := strings.Replace(string(b), "/*CONFIG_JSON*/", configJSON, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})

	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			dataMu.Lock()
			b, _ := json.Marshal(appData)
			dataMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			var newData AppData
			if err := json.Unmarshal(b, &newData); err == nil {
				dataMu.Lock()
				appData = newData
				dataMu.Unlock()
				saveLogs = newData.Settings.SaveLogs
				saveDataFile()
				w.WriteHeader(200)
			} else {
				w.WriteHeader(400)
			}
		}
	})

	http.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node")
		if nodeID == "" {
			nodeID = "auto"
		}
		dataMu.Lock()
		appData.SelectedNode = nodeID
		appData.ProxyRunning = true
		b, err := generateSingboxConfig(appData, nodeID)
		dataMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		os.WriteFile("donjuan-data/config.json", b, 0644)
		saveDataFile()

		if err := startSingbox(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		dataMu.Lock()
		appData.ProxyRunning = false
		dataMu.Unlock()
		saveDataFile()
		stopSingbox()
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		running := false
		if err := exec.Command("pgrep", "-f", "sing-box run").Run(); err == nil {
			running = true
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"running": running,
		})
	})

	http.HandleFunc("/api/cleanup", func(w http.ResponseWriter, r *http.Request) {
		stopSingbox()
b, err := os.ReadFile("donjuan-data/data.json")
		if err == nil {
			var newData AppData
			if err := json.Unmarshal(b, &newData); err == nil {
				appData = newData
			}
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		logs := getLogs()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	})

	http.HandleFunc("/api/sysinfo", func(w http.ResponseWriter, r *http.Request) {
		ver := getSingboxVersion()
		installed := ver != ""
		osType := detectOS()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":   ver,
			"installed": installed,
			"os":        osType,
		})
	})

	http.HandleFunc("/api/install-singbox", func(w http.ResponseWriter, r *http.Request) {
		version := r.URL.Query().Get("version")
		osType := detectOS()
		var cmd *exec.Cmd

		hasVersion := version != ""
		isDebian := strings.HasPrefix(osType, "debian") || strings.HasPrefix(osType, "ubuntu") || strings.HasPrefix(osType, "linuxmint")
		isRedhat := strings.HasPrefix(osType, "fedora") || strings.HasPrefix(osType, "rhel") || strings.HasPrefix(osType, "centos") || strings.HasPrefix(osType, "rocky") || strings.HasPrefix(osType, "almalinux")
		isOpenwrt := strings.HasPrefix(osType, "openwrt")
		isWindows := strings.HasPrefix(osType, "windows")

		if hasVersion && isDebian {
			arch := runtime.GOARCH
			if arch == "arm64" {
				arch = "arm64"
			} else if arch == "amd64" {
				arch = "amd64"
			} else if strings.HasPrefix(arch, "arm") {
				arch = "armv7"
			}
			script := fmt.Sprintf("curl -fsSL https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz -o /tmp/sing-box.tar.gz && tar -xzf /tmp/sing-box.tar.gz -C /tmp && mv /tmp/sing-box-%s-linux-%s/sing-box /usr/local/bin/sing-box && chmod +x /usr/local/bin/sing-box && rm -rf /tmp/sing-box*", version, version, arch, version, arch)
			cmd = exec.Command("bash", "-c", script)
		} else if hasVersion && isOpenwrt {
			cmd = exec.Command("sh", "-c", fmt.Sprintf("opkg update && opkg install sing-box kmod-tun ca-bundle && curl -fsSL https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-arm64.tar.gz -o /tmp/sing-box.tar.gz && tar -xzf /tmp/sing-box.tar.gz -C /tmp && mv /tmp/sing-box-%s-linux-arm64/sing-box /usr/bin/sing-box && chmod +x /usr/bin/sing-box && rm -rf /tmp/sing-box*", version, version, version))
		} else {
			switch {
			case isDebian:
				script := "mkdir -p /etc/apt/keyrings && curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc && chmod a+r /etc/apt/keyrings/sagernet.asc && printf 'Types: deb\\nURIs: https://deb.sagernet.org/\\nSuites: *\\nComponents: *\\nEnabled: yes\\nSigned-By: /etc/apt/keyrings/sagernet.asc\\n' > /etc/apt/sources.list.d/sagernet.sources && apt-get update && apt-get install -y sing-box"
				cmd = exec.Command("bash", "-c", script)
			case isRedhat:
				cmd = exec.Command("bash", "-c", "dnf config-manager addrepo --from-repofile=https://sing-box.app/sing-box.repo && dnf install -y sing-box")
			case isOpenwrt:
				cmd = exec.Command("sh", "-c", "opkg update && opkg install sing-box kmod-tun ca-bundle")
			case isWindows:
				cmd = exec.Command("winget", "install", "sing-box")
			default:
				http.Error(w, "Unsupported OS. Visit https://sing-box.sagernet.org/installation/package-manager/", 400)
				return
			}
		}

		out, err := cmd.CombinedOutput()
		addLog("Install output: " + string(out))
		if err != nil {
			http.Error(w, fmt.Sprintf("Install failed: %s\n%s", err, string(out)), 500)
			return
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/restart-ui", func(w http.ResponseWriter, r *http.Request) {
		forceCleanup()
		w.Write([]byte("Restarting..."))
		go func() {
			time.Sleep(1 * time.Second)
			execPath, _ := os.Executable()
			cmd := exec.Command(execPath, os.Args[1:]...)
			cmd.Stdin = nil
			cmd.Stdout = nil
			cmd.Stderr = nil
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Start()
			os.Exit(0)
		}()
	})

	http.HandleFunc("/api/test-latency", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("id")
		nodeURL := r.URL.Query().Get("url")
		if nodeID == "" || nodeURL == "" {
			http.Error(w, "missing id or url", 400)
			return
		}

		// Try Clash API first (works if proxy is currently running)
		clashUrl := fmt.Sprintf("http://127.0.0.1:9090/proxies/proxy-%s/delay?timeout=5000&url=http://cp.cloudflare.com/generate_204", nodeID)
		resp, err := http.Get(clashUrl)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				var res map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&res)
				if delay, ok := res["delay"].(float64); ok && delay > 0 {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{"ms": int64(delay)})
					return
				}
			}
		}

		// Fallback to real latency test via temporary sing-box instance
		ms := testRealLatency(nodeURL)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ms": ms})
	})

	http.HandleFunc("/api/fetch-subscription", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
			http.Error(w, "missing url", 400)
			return
		}
		details, nodes, unsupported, err := fetchSubscription(req.URL)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"details":     details,
			"nodes":       nodes,
			"unsupported": unsupported,
		})
	})

	http.HandleFunc("/api/download-geodata", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing name", 400)
			return
		}
		os.MkdirAll("donjuan-data", 0755)

		var dlURL string
		if strings.HasPrefix(name, "geoip-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs", name)
		} else if strings.HasPrefix(name, "geosite-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs", name)
		} else {
			http.Error(w, "invalid prefix", 400)
			return
		}

		destFile := fmt.Sprintf("donjuan-data/%s.srs", name)

		// Delete 0-byte or corrupt files so they can be re-downloaded
		if stat, err := os.Stat(destFile); err == nil && stat.Size() == 0 {
			os.Remove(destFile)
		}

		type dlResult struct {
			File string `json:"file"`
			Size int64  `json:"size"`
			Err  string `json:"error,omitempty"`
		}

		if stat, err := os.Stat(destFile); err == nil && stat.Size() > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]dlResult{{File: name + ".srs", Size: stat.Size()}})
			return
		}

		sz, err := downloadFile(dlURL, destFile)
		res := dlResult{File: name + ".srs", Size: sz}
		if err != nil {
			// Remove 0-byte file if download failed
			os.Remove(destFile)
			res.Err = err.Error()
		} else if sz == 0 {
			os.Remove(destFile)
			res.Err = "downloaded file is empty"
			res.Size = 0
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]dlResult{res})
	})

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("donjuan-data/config.json")
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	http.HandleFunc("/api/clear-logs", func(w http.ResponseWriter, r *http.Request) {
		logMu.Lock()
		if currentLogFile != nil {
			currentLogFile.Close()
			currentLogFile = nil
			currentLogDate = ""
		}
		logBuffer = nil
		logMu.Unlock()
		files, _ := os.ReadDir("donjuan-data")
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".log") {
				os.Remove("donjuan-data/" + f.Name())
			}
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		stopSingbox()
		os.Remove("donjuan-data/data.json")
		os.Remove("donjuan-data/config.json")
		os.RemoveAll("donjuan-data")
		w.WriteHeader(200)
		go func() {
			time.Sleep(1 * time.Second)
			execPath, _ := os.Executable()
			cmd := exec.Command(execPath, os.Args[1:]...)
			cmd.Stdin = nil
			cmd.Stdout = nil
			cmd.Stderr = nil
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Start()
			os.Exit(0)
		}()
	})

	os.MkdirAll("donjuan-data", 0755)
	addr := fmt.Sprintf(":%d", appData.Port)
	log.Printf("Starting UI on http://127.0.0.1%s", addr)

	// Auto-start proxy if it was running before restart
	if appData.ProxyRunning && len(allNodes(appData)) > 0 {
		go func() {
			time.Sleep(1 * time.Second)
			nodeID := appData.SelectedNode
			if nodeID == "" {
				nodeID = "auto"
			}
			dataMu.Lock()
			b, err := generateSingboxConfig(appData, nodeID)
			dataMu.Unlock()
			if err == nil {
os.WriteFile("donjuan-data/config.json", b, 0644)
				if err := startSingbox(); err != nil {
					addLog("Auto-start failed: " + err.Error())
				} else {
					addLog("Auto-started proxy")
				}
			}
		}()
	}

	http.ListenAndServe(addr, nil)
}

func downloadFile(dlURL, dest string) (int64, error) {
	sz, err := downloadFileWithTLS(dlURL, dest, false)
	if err != nil {
		// Fallback: retry with insecure TLS (common on OpenWrt without CA bundle)
		os.Remove(dest)
		sz, err2 := downloadFileWithTLS(dlURL, dest, true)
		if err2 != nil {
			return 0, fmt.Errorf("TLS secure: %v; TLS insecure: %v", err, err2)
		}
		return sz, nil
	}
	return sz, nil
}

func downloadFileWithTLS(dlURL, dest string, insecure bool) (int64, error) {
	out, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	client := &http.Client{Timeout: 60 * time.Second}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Get(dlURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("bad status: %s", resp.Status)
	}
	return io.Copy(out, resp.Body)
}

func testRealLatency(nodeURL string) int64 {
	outbound, err := parseNodeURL(nodeURL, true)
	if err != nil {
		return -1
	}

	rand.Seed(time.Now().UnixNano())
	port := 15000 + rand.Intn(10000)

	config := map[string]interface{}{
		"log": map[string]interface{}{"level": "fatal"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": port,
			},
		},
		"outbounds": []interface{}{outbound},
	}

	b, _ := json.Marshal(config)
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("test-%d.json", port))
	os.WriteFile(tmpFile, b, 0644)
	defer os.Remove(tmpFile)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, findSingbox(), "run", "-c", tmpFile)
	if err := cmd.Start(); err != nil {
		return -1
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for sing-box to listen
	time.Sleep(500 * time.Millisecond)

	proxyUrl, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("http://cp.cloudflare.com/generate_204")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 204 {
		return -1
	}

	return time.Since(start).Milliseconds()
}

func generateID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 7)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func parseSubscriptionContent(content string) (string, []Node, int) {
	lines := strings.Split(content, "\n")
	var details string
	var nodes []Node
	var unsupported int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "details://") {
			details = strings.TrimPrefix(line, "details://")
			continue
		}
		var protoType string
		if strings.HasPrefix(line, "vless://") {
			protoType = "vless"
		} else if strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://") {
			protoType = "hy2"
		} else if strings.HasPrefix(line, "trojan://") {
			protoType = "trojan"
		} else {
			unsupported++
			continue
		}
		_, err := parseNodeURL(line, false)
		if err != nil {
			unsupported++
			continue
		}
		remarks := ""
		domain := ""
		u, urlErr := url.Parse(line)
		if urlErr == nil {
			domain = u.Hostname()
			if u.Fragment != "" {
				remarks, _ = url.PathUnescape(u.Fragment)
			}
		}
		if remarks == "" {
			remarks = protoType + " Node"
		}
		nodes = append(nodes, Node{
			ID:      generateID(),
			Remarks: remarks,
			Type:    protoType,
			URL:     line,
			Domain:  domain,
			Latency: 0,
		})
	}
	return details, nodes, unsupported
}

func fetchSubscription(subURL string) (string, []Node, int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(subURL)
	if err != nil {
		return "", nil, 0, fmt.Errorf("fetch failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", nil, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read failed: %v", err)
	}

	content := strings.TrimSpace(string(body))
	decoded := ""
	raw, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(content)
		if err != nil {
			decoded = content
		} else {
			decoded = string(raw)
		}
	} else {
		decoded = string(raw)
	}

	if decoded == "" || !strings.Contains(decoded, "://") {
		decoded = content
	}

	details, nodes, unsupported := parseSubscriptionContent(decoded)
	return details, nodes, unsupported, nil
}

func allNodes(data AppData) []Node {
	var nodes []Node
	nodes = append(nodes, data.Nodes...)
	for _, sub := range data.Subscriptions {
		nodes = append(nodes, sub.Nodes...)
	}
	return nodes
}
