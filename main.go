package main

import (
	"context"
	"embed"
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

	b, err := os.ReadFile("data.json")
	if err == nil {
		json.Unmarshal(b, &appData)
	}
	saveLogs = appData.Settings.SaveLogs
}

func saveDataFile() {
	dataMu.Lock()
	defer dataMu.Unlock()
	b, _ := json.MarshalIndent(appData, "", "  ")
	os.WriteFile("data.json", b, 0644)
}

func detectOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	default:
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			return "debian"
		}
		if _, err := exec.LookPath("apt-get"); err == nil {
			return "debian"
		}
		if _, err := os.Stat("/etc/redhat-release"); err == nil {
			return "redhat"
		}
		if _, err := exec.LookPath("dnf"); err == nil {
			return "redhat"
		}
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			if contains(string(b), "OpenWrt") {
				return "openwrt"
			}
		}
		return "other"
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsImpl(s, sub))
}
func containsImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func main() {
	loadData()
	if appData.Port == 0 {
		appData.Port = 8080
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
		configData, _ := os.ReadFile("config.json")
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
		b, err := generateSingboxConfig(appData, nodeID)
		dataMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		os.WriteFile("config.json", b, 0644)
		saveDataFile()

		if err := startSingbox(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
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
		b, err := os.ReadFile("data.json")
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

		if version != "" && osType == "debian" {
			// For specific version on debian (assuming linux/amd64 for now, could be improved)
			script := fmt.Sprintf(`curl -fsSL https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz -o /tmp/sing-box.tar.gz && tar -xzf /tmp/sing-box.tar.gz -C /tmp && mv /tmp/sing-box-%s-linux-amd64/sing-box /usr/local/bin/sing-box && chmod +x /usr/local/bin/sing-box && rm -rf /tmp/sing-box*`, version, version, version)
			cmd = exec.Command("bash", "-c", script)
		} else {
			switch osType {
			case "debian":
				script := `mkdir -p /etc/apt/keyrings && curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc && chmod a+r /etc/apt/keyrings/sagernet.asc && echo 'Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc' > /etc/apt/sources.list.d/sagernet.sources && apt-get update && apt-get install -y sing-box`
				cmd = exec.Command("bash", "-c", script)
			case "redhat":
				cmd = exec.Command("bash", "-c", "dnf config-manager addrepo --from-repofile=https://sing-box.app/sing-box.repo && dnf install -y sing-box")
			case "openwrt":
				cmd = exec.Command("sh", "-c", "opkg update && opkg install sing-box kmod-tun ca-bundle")
			case "windows":
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
		w.Write([]byte("Restarting..."))
		go func() {
			time.Sleep(1 * time.Second)
			cmd := exec.Command(os.Args[0], os.Args[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
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

	http.HandleFunc("/api/download-geodata", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing name", 400)
			return
		}
		os.MkdirAll("data", 0755)

		var dlURL string
		if strings.HasPrefix(name, "geoip-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs", name)
		} else if strings.HasPrefix(name, "geosite-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs", name)
		} else {
			http.Error(w, "invalid prefix", 400)
			return
		}

		destFile := fmt.Sprintf("data/%s.srs", name)

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
			res.Err = err.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]dlResult{res})
	})

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("config.json")
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
		files, _ := os.ReadDir("data")
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".log") {
				os.Remove("data/" + f.Name())
			}
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		stopSingbox()
		os.Remove("data.json")
		os.Remove("config.json")
		os.RemoveAll("data")
		w.WriteHeader(200)
		go func() {
			time.Sleep(1 * time.Second)
			cmd := exec.Command(os.Args[0], os.Args[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Start()
			os.Exit(0)
		}()
	})

	os.MkdirAll("data", 0755)
	addr := fmt.Sprintf(":%d", appData.Port)
	log.Printf("Starting UI on http://127.0.0.1%s", addr)
	http.ListenAndServe(addr, nil)
}

func downloadFile(url, dest string) (int64, error) {
	out, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	resp, err := http.Get(url)
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

	cmd := exec.CommandContext(ctx, "./sing-box", "run", "-c", tmpFile)
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
