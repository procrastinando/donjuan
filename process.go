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
os.MkdirAll("donjuan-data", 0755)
	f, err := os.OpenFile(fmt.Sprintf("donjuan-data/%s.log", today), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
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

// killAllSingbox is the nuclear option — kills ALL sing-box processes system-wide
func killAllSingbox() {
	if runtime.GOOS == "windows" {
		exec.Command("taskkill", "/F", "/IM", "sing-box.exe").Run()
	} else {
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

func startSingbox() error {
	processMu.Lock()
	defer processMu.Unlock()

	// ALWAYS do a full cleanup before starting, regardless of state
	if singboxCmd != nil && singboxCmd.Process != nil {
		singboxCmd.Process.Kill()
		singboxCmd.Wait()
	}
	killAllSingbox()
	time.Sleep(300 * time.Millisecond)
	removeTUN()
	time.Sleep(200 * time.Millisecond)
	singboxCmd = nil

	cmdPath := findSingbox()
	cmd := exec.Command(cmdPath, "run", "-c", "donjuan-data/config.json")

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
		cmd.Wait()
		processMu.Lock()
		singboxCmd = nil
		processMu.Unlock()
	}()

	return nil
}

func stopSingboxLocked() {
	// First try graceful kill of tracked process
	if singboxCmd != nil && singboxCmd.Process != nil {
		singboxCmd.Process.Kill()
		done := make(chan struct{})
		go func() { singboxCmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	// Nuclear fallback: kill ALL sing-box processes
	killAllSingbox()
	time.Sleep(300 * time.Millisecond)

	// Clean TUN interface
	removeTUN()

	singboxCmd = nil
	addLog("sing-box stopped and TUN cleaned")
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
	removeTUN()

	// Flush DNS
	if runtime.GOOS == "windows" {
		exec.Command("ipconfig", "/flushdns").Run()
	} else if runtime.GOOS == "linux" {
		exec.Command("resolvectl", "flush-caches").Run()
	}
	addLog("Force cleanup completed — all sing-box processes killed, TUN removed, DNS flushed")
}
