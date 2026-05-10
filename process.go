package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	singboxCmd     *exec.Cmd
	logBuffer      []string
	logMu          sync.Mutex
	processMu      sync.Mutex
	currentLogFile *os.File
	currentLogDate string
	saveLogs       bool
)

func addLog(msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, msg)
	logBuffer = append(logBuffer, entry)
	if len(logBuffer) > 500 {
		logBuffer = logBuffer[1:]
	}
	if saveLogs {
		writeToLogFile(entry)
	}
}

func writeToLogFile(entry string) {
	today := time.Now().Format("2006-01-02")
	if currentLogFile == nil || currentLogDate != today {
		if currentLogFile != nil {
			currentLogFile.Close()
		}
		os.MkdirAll("/etc/donjuan", 0755)
		f, err := os.OpenFile(fmt.Sprintf("/tmp/donjuan-%s.log", today), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		currentLogFile = f
		currentLogDate = today
	}
	currentLogFile.WriteString(entry + "\n")
}

func getLogs() []string {
	logMu.Lock()
	defer logMu.Unlock()
	return append([]string(nil), logBuffer...)
}

func findSingbox() string {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name = "sing-box.exe"
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if _, err := os.Stat("./" + name); err == nil {
		return "./" + name
	}
	return name
}

func getSingboxVersion() string {
	out, err := exec.Command(findSingbox(), "version").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		v := strings.TrimSpace(lines[0])
		v = strings.TrimPrefix(v, "sing-box version ")
		return v
	}
	return ""
}

// killAllSingbox sends SIGTERM first, then SIGKILL as fallback
func killAllSingbox() {
	if runtime.GOOS == "windows" {
		exec.Command("taskkill", "/F", "/IM", "sing-box.exe").Run()
	} else {
		// SIGTERM first for graceful cleanup of routes/nftables
		exec.Command("pkill", "-15", "-f", "sing-box").Run()
		time.Sleep(2 * time.Second)
		// SIGKILL any survivors
		exec.Command("pkill", "-9", "-f", "sing-box").Run()
	}
}

func removeTUN() {
	if runtime.GOOS == "windows" {
		exec.Command("netsh", "interface", "set", "interface", "name=\"tun-in\"", "admin=disable").Run()
	} else {
		exec.Command("ip", "link", "delete", "tun-in").Run()
	}
}

// cleanupRouting removes leftover routing rules and nftables chains that
// sing-box creates with auto_route/strict_route. Without this cleanup,
// stopping sing-box leaves traffic routed into a dead TUN = network blackhole.
func cleanupRouting() {
	if runtime.GOOS == "windows" {
		return
	}

	// Remove ip rules pointing to sing-box routing tables (typically 9000-9003)
	for _, table := range []string{"9000", "9001", "9002", "9003"} {
		for i := 0; i < 5; i++ {
			if err := exec.Command("ip", "rule", "del", "table", table).Run(); err != nil {
				break
			}
		}
		exec.Command("ip", "route", "flush", "table", table).Run()
	}

	// Clean up nftables chains created by sing-box
	out, err := exec.Command("nft", "list", "tables").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "sing-box") || strings.Contains(line, "singbox") {
				// e.g., "table inet sing-box" → delete it
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					exec.Command("nft", "delete", parts[0], parts[1], parts[2]).Run()
				}
			}
		}
	}

	// Flush any remaining sing-box iptables rules (legacy fallback)
	exec.Command("iptables", "-t", "mangle", "-F").Run()
	exec.Command("iptables", "-t", "mangle", "-X").Run()

	addLog("Routing cleanup completed (ip rules, nftables, iptables)")
}

func startSingbox() error {
	processMu.Lock()
	defer processMu.Unlock()

	// ALWAYS do a full cleanup before starting, regardless of state
	if singboxCmd != nil && singboxCmd.Process != nil {
		singboxCmd.Process.Signal(os.Interrupt) // SIGTERM
		done := make(chan struct{})
		go func() { singboxCmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			singboxCmd.Process.Kill()
			singboxCmd.Wait()
		}
	}
	killAllSingbox()
	time.Sleep(300 * time.Millisecond)
	cleanupRouting()
	removeTUN()
	time.Sleep(200 * time.Millisecond)
	singboxCmd = nil

	cmdPath := findSingbox()
	cmd := exec.Command(cmdPath, "run", "-c", "/etc/donjuan/config.json")

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	err := cmd.Start()
	if err != nil {
		addLog("ERROR: Failed to start sing-box: " + err.Error())
		log.Println("Error starting sing-box:", err)
		return err
	}

	singboxCmd = cmd
	addLog(fmt.Sprintf("sing-box started (PID %d)", cmd.Process.Pid))

	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stderr, stdout))
		for scanner.Scan() {
			addLog(scanner.Text())
		}
	}()

	go func() {
		err := cmd.Wait()
		if err != nil {
			addLog("sing-box exited with error: " + err.Error())
		} else {
			addLog("sing-box exited cleanly")
		}
		processMu.Lock()
		singboxCmd = nil
		processMu.Unlock()

		// Always ensure routing is cleaned up when process dies,
		// otherwise traffic is blackholed into a dead TUN interface!
		time.Sleep(500 * time.Millisecond)
		cleanupRouting()
		removeTUN()
	}()

	return nil
}

func stopSingboxLocked() {
	// First try graceful shutdown via SIGTERM (allows sing-box to clean up routes)
	if singboxCmd != nil && singboxCmd.Process != nil {
		singboxCmd.Process.Signal(os.Interrupt) // SIGTERM / SIGINT
		done := make(chan struct{})
		go func() { singboxCmd.Wait(); close(done) }()
		select {
		case <-done:
			addLog("sing-box stopped gracefully")
		case <-time.After(5 * time.Second):
			singboxCmd.Process.Kill()
			singboxCmd.Wait()
			addLog("sing-box force-killed after timeout")
		}
	}

	// Nuclear fallback: kill ALL sing-box processes
	killAllSingbox()
	time.Sleep(500 * time.Millisecond)

	// Clean up any leftover routing rules/nftables from strict_route/auto_route
	cleanupRouting()

	// Clean TUN interface
	removeTUN()

	singboxCmd = nil
	addLog("sing-box stopped and routing cleaned")
}

func stopSingbox() error {
	processMu.Lock()
	defer processMu.Unlock()
	stopSingboxLocked()
	return nil
}

func forceCleanup() {
	processMu.Lock()
	stopSingboxLocked()
	processMu.Unlock()

	// Extra: kill any remaining sing-box
	killAllSingbox()
	time.Sleep(500 * time.Millisecond)
	cleanupRouting()
	removeTUN()

	// Flush DNS
	if runtime.GOOS == "windows" {
		exec.Command("ipconfig", "/flushdns").Run()
	} else if runtime.GOOS == "linux" {
		exec.Command("resolvectl", "flush-caches").Run()
	}
	addLog("Force cleanup completed — all sing-box processes killed, routes cleaned, TUN removed, DNS flushed")
}
