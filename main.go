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

//go:embed index.html logo.svg
var content embed.FS

var (
	DonJuanVersion   = "v0.1.1"
	DonJuanBaseURL   = "https://donjuanvpn.com"
	appData          AppData
	dataMu           sync.Mutex
	authTokenStore = make(map[string]time.Time)
	authTokenMu    sync.Mutex
	routerConfig   RouterConfig
	routerConfigMu sync.Mutex
)

func loadData() {
	dataMu.Lock()
	defer dataMu.Unlock()
	
	// Set Defaults
	appData.Port = 8888
	appData.Settings.FakeIP = true
	appData.Settings.TUN = true
	appData.Settings.Sniffing = true
	appData.Settings.LocalNetwork = true

	b, err := os.ReadFile("/etc/donjuan/data.json")
	if err == nil {
		json.Unmarshal(b, &appData)
	}
	saveLogs = appData.Settings.SaveLogs
}

func loadRouterConfig() {
	routerConfigMu.Lock()
	defer routerConfigMu.Unlock()

	routerConfig.Password = "donjuan"
	routerConfig.LuciURL = "http://192.168.1.1"
	routerConfig.RadioDevices = []string{"radio0", "radio1"}
	routerConfig.RadioBands = map[string]string{"radio0": "2g", "radio1": "5g"}

	b, err := os.ReadFile("/etc/donjuan/router.json")
	if err == nil {
		json.Unmarshal(b, &routerConfig)
	}
}

func saveRouterConfigFile() {
	routerConfigMu.Lock()
	defer routerConfigMu.Unlock()
	os.MkdirAll("/etc/donjuan", 0755)
	b, _ := json.MarshalIndent(routerConfig, "", "  ")
	os.WriteFile("/etc/donjuan/router.json", b, 0644)
}

func saveDataFile() {
	dataMu.Lock()
	defer dataMu.Unlock()
	b, _ := json.MarshalIndent(appData, "", "  ")
	os.WriteFile("/etc/donjuan/data.json", b, 0644)
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

var loginPageHTML = `<!DOCTYPE html><html lang="en" class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>DonJuan VPN</title><link rel="icon" type="image/svg+xml" href="logo.svg"><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={darkMode:'class',theme:{extend:{colors:{darkBg:'#0f172a',darkCard:'#1e293b'}}}}</script><style>body{background:#0f172a;color:#f8fafc;font-family:'Inter',sans-serif}</style></head><body class="antialiased min-h-screen flex items-center justify-center p-4"><div class="bg-darkCard rounded-xl border border-slate-700 w-full max-w-sm p-8 shadow-2xl"><div class="text-center mb-6"><a href="https://donjuanvpn.com" target="_blank" class="flex items-center justify-center space-x-2 text-2xl font-bold bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent"><span>DonJuan VPN</span></a><p class="text-slate-400 text-sm mt-2">Enter password to access</p></div><div id="error" class="hidden mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-400 text-sm"></div><div class="mb-4"><input type="password" id="pw" placeholder="Password" class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" onkeydown="if(event.key==='Enter')login()"></div><button id="btn" onclick="login()" class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium">Login</button></div><script>function login(){const p=document.getElementById('pw').value;const e=document.getElementById('error');const b=document.getElementById('btn');b.disabled=true;b.textContent='Logging in...';e.classList.add('hidden');fetch('/api/openwrt/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})}).then(r=>r.json()).then(d=>{if(d.token){localStorage.setItem('openwrt_token',d.token);window.location.reload()}else{e.textContent='Invalid password';e.classList.remove('hidden');b.disabled=false;b.textContent='Login'}}).catch(()=>{e.textContent='Connection error';e.classList.remove('hidden');b.disabled=false;b.textContent='Login'})}</script></body></html>`

func main() {
	loadData()
	loadRouterConfig()
	if _, err := os.Stat("/etc/donjuan/router.json"); os.IsNotExist(err) {
		saveRouterConfigFile()
	}
	if appData.Port == 0 {
		appData.Port = 8888
	}

	if os.Getenv("DONJUAN_DAEMONIZED") != "1" {
		os.MkdirAll("/etc/donjuan", 0755)
		execPath, _ := os.Executable()
		cmd := exec.Command(execPath, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "DONJUAN_DAEMONIZED=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Start()
		fmt.Printf("DonJuan VPN started in background (PID %d)\n", cmd.Process.Pid)
		os.Exit(0)
	}

	logFile, _ := os.OpenFile("/tmp/donjuan.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if logFile != nil {
		log.SetOutput(logFile)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logo.svg" {
			b, err := content.ReadFile("logo.svg")
			if err == nil {
				w.Header().Set("Content-Type", "image/svg+xml")
				w.Write(b)
				return
			}
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := content.ReadFile("index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		configData, _ := os.ReadFile("/etc/donjuan/config.json")
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
		os.WriteFile("/etc/donjuan/config.json", b, 0644)
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
		dataMu.Lock()
		running := appData.ProxyRunning
		dataMu.Unlock()
		
		if running {
			actuallyRunning := false
			processMu.Lock()
			if singboxCmd != nil && singboxCmd.Process != nil {
				actuallyRunning = true
			}
			processMu.Unlock()
			if !actuallyRunning {
				if out, err := exec.Command("pidof", "sing-box").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
					actuallyRunning = true
				} else if err := exec.Command("pgrep", "-x", "sing-box").Run(); err == nil {
					actuallyRunning = true
				}
			}
			if !actuallyRunning {
				dataMu.Lock()
				appData.ProxyRunning = false
				running = false
				dataMu.Unlock()
				saveDataFile()
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"running": running,
		})
	})

	http.HandleFunc("/api/cleanup", func(w http.ResponseWriter, r *http.Request) {
		stopSingbox()
b, err := os.ReadFile("/etc/donjuan/data.json")
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
			"version":        ver,
			"installed":      installed,
			"os":             osType,
			"donjuanVersion": DonJuanVersion,
			"donjuanBaseURL": DonJuanBaseURL,
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

	http.HandleFunc("/api/reboot-router", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("reboot").Run()
		}()
		w.Write([]byte("Rebooting..."))
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
		os.MkdirAll("/etc/donjuan", 0755)

		var dlURL string
		if strings.HasPrefix(name, "geoip-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs", name)
		} else if strings.HasPrefix(name, "geosite-") {
			dlURL = fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs", name)
		} else {
			http.Error(w, "invalid prefix", 400)
			return
		}

		destFile := fmt.Sprintf("/etc/donjuan/%s.srs", name)

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
		b, err := os.ReadFile("/etc/donjuan/config.json")
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
		files, _ := os.ReadDir("/etc/donjuan")
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".log") {
				os.Remove("/etc/donjuan/" + f.Name())
			}
		}
		w.WriteHeader(200)
	})

	http.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		stopSingbox()
		os.Remove("/etc/donjuan/data.json")
		os.Remove("/etc/donjuan/config.json")
		os.RemoveAll("/etc/donjuan")
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

	// Router config endpoint
	http.HandleFunc("/api/router-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			routerConfigMu.Lock()
			b, _ := json.Marshal(routerConfig)
			routerConfigMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			var newConfig RouterConfig
			if err := json.Unmarshal(b, &newConfig); err == nil {
				routerConfigMu.Lock()
				routerConfig = newConfig
				routerConfigMu.Unlock()
				saveRouterConfigFile()
				w.WriteHeader(200)
			} else {
				w.WriteHeader(400)
			}
		}
	})

	// OpenWrt authentication endpoint (exempt from auth middleware)
	http.HandleFunc("/api/openwrt/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(400)
			return
		}
		routerConfigMu.Lock()
		password := routerConfig.Password
		routerConfigMu.Unlock()
		if password == "" {
			password = "donjuan"
		}
		if req.Password != password {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_password"})
			return
		}
		token := generateToken()
		authTokenMu.Lock()
		authTokenStore[token] = time.Now().Add(24 * time.Hour)
		authTokenMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "openwrt_token", Value: token, Path: "/", MaxAge: 86400, HttpOnly: false, SameSite: http.SameSiteStrictMode})
		json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
	})

	http.HandleFunc("/api/openwrt/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			authTokenMu.Lock()
			delete(authTokenStore, token)
			authTokenMu.Unlock()
		}
		if c, err := r.Cookie("openwrt_token"); err == nil {
			authTokenMu.Lock()
			delete(authTokenStore, c.Value)
			authTokenMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "openwrt_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: false})
		w.WriteHeader(200)
	})

	// OpenWrt: change password
	http.HandleFunc("/api/openwrt/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
			w.WriteHeader(400)
			return
		}
		routerConfigMu.Lock()
		routerConfig.Password = req.Password
		routerConfigMu.Unlock()
		saveRouterConfigFile()
		w.WriteHeader(200)
	})

	// OpenWrt: get wireless status
	http.HandleFunc("/api/openwrt/status", func(w http.ResponseWriter, r *http.Request) {
		dataMu.Lock()
		isOpenwrt := appData.Settings.OpenwrtMode
		dataMu.Unlock()
		if !isOpenwrt {
			http.Error(w, "OpenWrt mode not enabled", 400)
			return
		}
		out, err := exec.Command("ubus", "call", "network.wireless", "status").Output()
		if err != nil {
			http.Error(w, "OpenWrt wireless tools not available: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})

	// OpenWrt: get system info
	http.HandleFunc("/api/openwrt/sysinfo", func(w http.ResponseWriter, r *http.Request) {
		dataMu.Lock()
		isOpenwrt := appData.Settings.OpenwrtMode
		dataMu.Unlock()
		if !isOpenwrt {
			http.Error(w, "OpenWrt mode not enabled", 400)
			return
		}
		out, err := exec.Command("ubus", "call", "system", "board").Output()
		if err != nil {
			http.Error(w, "OpenWrt system tools not available: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})

	// OpenWrt: scan WiFi networks
	http.HandleFunc("/api/openwrt/wifi-scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Devices []string `json:"devices"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Devices) == 0 {
			routerConfigMu.Lock()
			defDevices := routerConfig.RadioDevices
			routerConfigMu.Unlock()
			if len(defDevices) > 0 {
				req.Devices = defDevices
			} else {
				req.Devices = []string{"radio0", "radio1"}
			}
		}
		var results []map[string]interface{}
		for _, dev := range req.Devices {
			param := fmt.Sprintf(`{"device":"%s"}`, dev)
			out, err := exec.Command("ubus", "call", "iwinfo", "scan", param).Output()
			if err != nil {
				continue
			}
			var scanResult map[string]interface{}
			if err := json.Unmarshal(out, &scanResult); err != nil {
				continue
			}
			if res, ok := scanResult["results"].([]interface{}); ok {
				for _, r := range res {
					if m, ok := r.(map[string]interface{}); ok {
						m["device"] = dev
						results = append(results, m)
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
	})

	// OpenWrt: save WiFi configuration
	http.HandleFunc("/api/openwrt/wifi-save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Radios []struct {
				Device   string `json:"device"`
				Channel  string `json:"channel"`
				Htmode   string `json:"htmode"`
				Disabled *bool  `json:"disabled"`
			} `json:"radios"`
			Ifaces []struct {
				Section    string `json:"section"`
				Ssid       string `json:"ssid"`
				Key        string `json:"key"`
				Encryption string `json:"encryption"`
				Hidden     *bool  `json:"hidden"`
			} `json:"ifaces"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for _, radio := range req.Radios {
			if radio.Channel != "" {
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.channel=%s", radio.Device, radio.Channel)).Run()
			}
			if radio.Htmode != "" {
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.htmode=%s", radio.Device, radio.Htmode)).Run()
			}
			if radio.Disabled != nil {
				val := "0"
				if *radio.Disabled {
					val = "1"
				}
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.disabled=%s", radio.Device, val)).Run()
			}
		}
		for _, iface := range req.Ifaces {
			if iface.Ssid != "" {
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.ssid=%s", iface.Section, iface.Ssid)).Run()
			}
			if iface.Encryption != "" {
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.encryption=%s", iface.Section, iface.Encryption)).Run()
			}
			if iface.Key != "" {
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.key=%s", iface.Section, iface.Key)).Run()
			}
			if iface.Hidden != nil {
				val := "0"
				if *iface.Hidden {
					val = "1"
				}
				exec.Command("uci", "set", fmt.Sprintf("wireless.%s.hidden=%s", iface.Section, val)).Run()
			}
		}
		out, err := exec.Command("uci", "commit", "wireless").CombinedOutput()
		if err != nil {
			http.Error(w, fmt.Sprintf("uci commit failed: %s: %s", err, string(out)), 500)
			return
		}
		go func() {
			exec.Command("wifi", "reload").Run()
		}()
		w.WriteHeader(200)
	})

	// OpenWrt: get connected WiFi clients
	http.HandleFunc("/api/openwrt/wifi-clients", func(w http.ResponseWriter, r *http.Request) {
		wirelessOut, err := exec.Command("ubus", "call", "network.wireless", "status").Output()
		if err != nil {
			http.Error(w, "OpenWrt wireless tools not available", 500)
			return
		}
		var wirelessStatus map[string]interface{}
		if err := json.Unmarshal(wirelessOut, &wirelessStatus); err != nil {
			http.Error(w, "Failed to parse wireless status", 500)
			return
		}
		ifaceInfo := make(map[string]map[string]interface{})
		for radioName, radioVal := range wirelessStatus {
			radio, ok := radioVal.(map[string]interface{})
			if !ok {
				continue
			}
			radioConfig, _ := radio["config"].(map[string]interface{})
			band := "2g"
			if rc, ok := radioConfig["band"].(string); ok {
				band = rc
			}
			interfaces, ok := radio["interfaces"].([]interface{})
			if !ok {
				continue
			}
			for _, ifaceVal := range interfaces {
				iface, ok := ifaceVal.(map[string]interface{})
				if !ok {
					continue
				}
				ifname, _ := iface["ifname"].(string)
				config, _ := iface["config"].(map[string]interface{})
				ssid, _ := config["ssid"].(string)
				if ifname == "" {
					continue
				}
				ifaceInfo[ifname] = map[string]interface{}{
					"radio": radioName,
					"band":  band,
					"ssid":  ssid,
				}
			}
		}
		// Also read DHCP leases for hostnames and IPs
		// Format: timestamp MAC IP hostname clientid
		type leaseEntry struct {
			MAC      string
			IP       string
			Hostname string
		}
		var leases []leaseEntry
		if leaseData, err := os.ReadFile("/tmp/dhcp.leases"); err == nil {
			for _, line := range strings.Split(string(leaseData), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					hname := fields[3]
					if hname == "*" {
						hname = ""
					}
					leases = append(leases, leaseEntry{MAC: strings.ToLower(fields[1]), IP: fields[2], Hostname: hname})
				}
			}
		}
		hostapdOut, err := exec.Command("ubus", "list").Output()
		if err != nil {
			http.Error(w, "Failed to list hostapd interfaces", 500)
			return
		}
		var clients []map[string]interface{}
		for _, line := range strings.Split(string(hostapdOut), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "hostapd.") {
				continue
			}
			ifaceName := strings.TrimPrefix(line, "hostapd.")
			out, err := exec.Command("ubus", "call", line, "get_clients").Output()
			if err != nil {
				continue
			}
			var result map[string]interface{}
			if err := json.Unmarshal(out, &result); err != nil {
				continue
			}
			info := ifaceInfo[ifaceName]
			clientsList, ok := result["clients"].(map[string]interface{})
			if !ok {
				continue
			}
			for mac, clientVal := range clientsList {
				client, ok := clientVal.(map[string]interface{})
				if !ok {
					continue
				}
				hostname := ""
				clientIP := ""
				if h, ok := client["hostname"].(string); ok && h != "" {
					hostname = h
				}
				macLower := strings.ToLower(mac)
				for _, l := range leases {
					if l.MAC == macLower {
						if hostname == "" && l.Hostname != "" {
							hostname = l.Hostname
						}
						clientIP = l.IP
						break
					}
				}
				entry := map[string]interface{}{
					"mac":       mac,
					"iface":     ifaceName,
					"band":      "2g",
					"ssid":      "",
					"signal":    client["signal"],
					"auth":      client["auth"],
					"assoc":     client["assoc"],
					"authorized": client["authorized"],
					"hostname":  hostname,
					"ip":        clientIP,
				}
				if info != nil {
					entry["band"] = info["band"]
					entry["ssid"] = info["ssid"]
				}
				if bytes, ok := client["bytes"].(map[string]interface{}); ok {
					entry["rx_bytes"] = bytes["rx"]
					entry["tx_bytes"] = bytes["tx"]
				}
				if rate, ok := client["rate"].(map[string]interface{}); ok {
					entry["rx_rate"] = rate["rx"]
					entry["tx_rate"] = rate["tx"]
				}
				if ht, ok := client["ht"].(bool); ok {
					entry["ht"] = ht
				}
				if vht, ok := client["vht"].(bool); ok {
					entry["vht"] = vht
				}
				if he, ok := client["he"].(bool); ok {
					entry["he"] = he
				}
				clients = append(clients, entry)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"clients": clients})
	})

	// OpenWrt: disconnect a WiFi client
	http.HandleFunc("/api/openwrt/disconnect-client", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Iface string `json:"iface"`
			Mac   string `json:"mac"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Iface == "" || req.Mac == "" {
			w.WriteHeader(400)
			return
		}
		param := fmt.Sprintf(`{"addr":"%s","reason":5,"deauth":true,"ban_time":0}`, req.Mac)
		out, err := exec.Command("ubus", "call", "hostapd."+req.Iface, "del_client", param).CombinedOutput()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to disconnect client: %s: %s", err, string(out)), 500)
			return
		}
		w.WriteHeader(200)
	})

	// OpenWrt: connect to WiFi as client (STA mode)
	http.HandleFunc("/api/openwrt/wifi-connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			SSID       string `json:"ssid"`
			Key        string `json:"key"`
			Encryption string `json:"encryption"`
			Band       string `json:"band"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SSID == "" {
			http.Error(w, "missing ssid", 400)
			return
		}
		device := "radio0"
		routerConfigMu.Lock()
		bands := routerConfig.RadioBands
		routerConfigMu.Unlock()
		if len(bands) > 0 {
			for dev, band := range bands {
				if band == req.Band {
					device = dev
					break
				}
			}
		} else if req.Band == "5g" {
			device = "radio1"
		}
		// Remove any existing STA interface managed by donjuan
		exec.Command("uci", "delete", "wireless.sta_donjuan").Run()
		// Ensure wwan network interface exists
		exec.Command("uci", "set", "network.wwan=interface").Run()
		exec.Command("uci", "set", "network.wwan.proto=dhcp").Run()
		exec.Command("uci", "commit", "network").Run()
		// Add wwan to wan zone if it exists
		fwOut, _ := exec.Command("uci", "get", "firewall.@zone[1].network").Output()
		fwNetworks := strings.TrimSpace(string(fwOut))
		if !strings.Contains(fwNetworks, "wwan") {
			exec.Command("sh", "-c", "uci add_list firewall.@zone[1].network='wwan' && uci commit firewall").Run()
		}
		// Create named STA interface (avoids LuCI anonymous section migration)
		sectionName := "sta_donjuan"
		exec.Command("uci", "set", "wireless."+sectionName+"=wifi-iface").Run()
		exec.Command("uci", "set", fmt.Sprintf("wireless.%s.device=%s", sectionName, device)).Run()
		exec.Command("uci", "set", fmt.Sprintf("wireless.%s.mode=sta", sectionName)).Run()
		exec.Command("uci", "set", fmt.Sprintf("wireless.%s.ssid=%s", sectionName, req.SSID)).Run()
		exec.Command("uci", "set", fmt.Sprintf("wireless.%s.network=wwan", sectionName)).Run()
		if req.Encryption == "none" || req.Encryption == "" {
			exec.Command("uci", "set", fmt.Sprintf("wireless.%s.encryption=none", sectionName)).Run()
		} else {
			exec.Command("uci", "set", fmt.Sprintf("wireless.%s.encryption=%s", sectionName, req.Encryption)).Run()
			exec.Command("uci", "set", fmt.Sprintf("wireless.%s.key=%s", sectionName, req.Key)).Run()
		}
		exec.Command("uci", "commit", "wireless").Run()
		// Only reload wireless — do NOT restart the full network stack
		exec.Command("wifi", "reload").Run()
		// Save to remembered networks
		routerConfigMu.Lock()
		found := false
		for i, n := range routerConfig.WifiSTANetworks {
			if n.SSID == req.SSID {
				routerConfig.WifiSTANetworks[i].Key = req.Key
				routerConfig.WifiSTANetworks[i].Encryption = req.Encryption
				found = true
				break
			}
		}
		if !found {
			routerConfig.WifiSTANetworks = append(routerConfig.WifiSTANetworks, WifiSTANetwork{
				SSID:       req.SSID,
				Key:        req.Key,
				Encryption: req.Encryption,
				Band:       req.Band,
			})
		}
		routerConfigMu.Unlock()
		saveRouterConfigFile()
		w.WriteHeader(200)
	})

	// OpenWrt: disconnect STA (remove STA interface)
	http.HandleFunc("/api/openwrt/wifi-disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		// Remove the named STA interface
		exec.Command("uci", "delete", "wireless.sta_donjuan").Run()
		exec.Command("uci", "commit", "wireless").Run()
		// Only reload wireless — do NOT restart the full network
		exec.Command("wifi", "reload").Run()
		w.WriteHeader(200)
	})

	// OpenWrt: forget a saved WiFi network
	http.HandleFunc("/api/openwrt/wifi-forget", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req struct {
			SSID string `json:"ssid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SSID == "" {
			w.WriteHeader(400)
			return
		}
		// Check if the forgotten SSID is the currently connected STA
		staSSID := ""
		if out, err := exec.Command("uci", "get", "wireless.sta_donjuan.ssid").Output(); err == nil {
			staSSID = strings.TrimSpace(string(out))
		}
		if staSSID == req.SSID {
			// Disconnect the active STA since we're forgetting it
			exec.Command("uci", "delete", "wireless.sta_donjuan").Run()
			exec.Command("uci", "commit", "wireless").Run()
			exec.Command("wifi", "reload").Run()
		}
		// Remove from remembered networks only — no network restart
		routerConfigMu.Lock()
		var filtered []WifiSTANetwork
		for _, n := range routerConfig.WifiSTANetworks {
			if n.SSID != req.SSID {
				filtered = append(filtered, n)
			}
		}
		routerConfig.WifiSTANetworks = filtered
		routerConfigMu.Unlock()
		saveRouterConfigFile()
		w.WriteHeader(200)
	})

	os.MkdirAll("/etc/donjuan", 0755)
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
os.WriteFile("/etc/donjuan/config.json", b, 0644)
				if err := startSingbox(); err != nil {
					addLog("Auto-start failed: " + err.Error())
				} else {
					addLog("Auto-started proxy")
				}
			}
		}()
	}

	http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if appData.Settings.OpenwrtMode && r.URL.Path != "/api/openwrt/auth" && r.URL.Path != "/api/openwrt/logout" && r.URL.Path != "/favicon.ico" {
			valid := false
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				authTokenMu.Lock()
				if exp, ok := authTokenStore[token]; ok && time.Now().Before(exp) {
					valid = true
				}
				authTokenMu.Unlock()
			}
			if !valid {
				if c, err := r.Cookie("openwrt_token"); err == nil {
					authTokenMu.Lock()
					if exp, ok := authTokenStore[c.Value]; ok && time.Now().Before(exp) {
						valid = true
					}
					authTokenMu.Unlock()
				}
			}
			if !valid {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte(loginPageHTML))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "openwrt_auth_required"})
				return
			}
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	}))
}

func generateToken() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return fmt.Sprintf("%x", b)
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
