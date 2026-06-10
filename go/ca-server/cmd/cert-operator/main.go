package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const VERSION = "3.0.0"

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "get-cert":
		cmdGetCert(args)
	case "ssh":
		cmdSSH(args)
	case "deploy":
		cmdDeploy(args)
	case "version":
		fmt.Printf("cert-operator v%s\n", VERSION)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `cert-operator v%s — SSH certificate client

Usage:
  cert-operator get-cert <server> <totp> <name> [flags]   Get SSH cert from CA
  cert-operator ssh <host> <user> <key> [command]          SSH with certificate
  cert-operator deploy [script]                            Deploy client certs
  cert-operator version                                    Show version

Get-cert flags:
  --ca-cert PATH      CA HTTPS cert (default ~/.hermes/certs/ca-https-cert.pem)
  --client-cert PATH  mTLS client cert (default ~/.hermes/certs/client.cert)
  --client-key PATH   mTLS client key (default ~/.hermes/certs/client.key)
  --group NAME        Group name (default: "default")
  --user NAME         Username (default: server decides)

SSH flags:
  --port N            SSH port (default 22)
  --expires-at TIME   ISO 8601 expiry time for pre-check
`, VERSION)
}

func hermesDir() string {
	return filepath.Join(os.Getenv("HOME"), ".hermes", "certs")
}

func defaultPath(name string) string {
	return filepath.Join(hermesDir(), name)
}

// ---- get-cert -----------------------------------------------------------

func cmdGetCert(args []string) {
	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "用法: cert-operator get-cert <server> <totp> <name>\n")
		os.Exit(1)
	}
	server := args[0]
	totpCode := args[1]
	certName := args[2]

	// Parse flags
	flags := parseFlags(args[3:])
	caCert := flags["--ca-cert"]
	if caCert == "" { caCert = defaultPath("ca-https-cert.pem") }
	clientCert := flags["--client-cert"]
	if clientCert == "" { clientCert = defaultPath("client.cert") }
	clientKey := flags["--client-key"]
	if clientKey == "" { clientKey = defaultPath("client.key") }
	group := flags["--group"]
	user := flags["--user"]

	// Validate cert_name (prevent path traversal)
	if strings.Contains(certName, "/") || strings.Contains(certName, "\\") ||
		certName == "." || certName == ".." || strings.HasPrefix(certName, ".") {
		fmt.Fprintf(os.Stderr, "❌ cert_name 包含非法字符\n")
		os.Exit(1)
	}
	for _, c := range certName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			fmt.Fprintf(os.Stderr, "❌ cert_name 只能包含字母数字和-_.\n")
			os.Exit(1)
		}
	}

	// Validate TOTP
	if len(totpCode) != 6 {
		fmt.Fprintf(os.Stderr, "❌ TOTP 码需要6位数字\n")
		os.Exit(1)
	}
	for _, c := range totpCode {
		if c < '0' || c > '9' {
			fmt.Fprintf(os.Stderr, "❌ TOTP 码只能包含数字\n")
			os.Exit(1)
		}
	}

	// Build request body
	body := map[string]string{"totp": totpCode}
	if group != "" { body["group"] = group }
	if user != "" { body["user"] = user }
	bodyJSON, _ := json.Marshal(body)

	// Load TLS certs
	certPool := x509.NewCertPool()
	caData, err := os.ReadFile(caCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 无法读取 CA 证书: %s (%v)\n", caCert, err)
		os.Exit(1)
	}
	if !certPool.AppendCertsFromPEM(caData) {
		fmt.Fprintf(os.Stderr, "❌ 无法解析 CA 证书\n")
		os.Exit(1)
	}
	clientCertData, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 无法读取 mTLS 证书: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{clientCertData},
			},
		},
		Timeout: 30 * time.Second,
	}

	url := strings.TrimRight(server, "/") + "/api/get-cert"
	resp, err := client.Post(url, "application/json", strings.NewReader(string(bodyJSON)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 请求失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respData, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respData, &result)

	if !isTrue(result["success"]) {
		errMsg, _ := result["error"].(string)
		fmt.Fprintf(os.Stderr, "❌ %s\n", errMsg)
		os.Exit(1)
	}

	// Save key and cert
	outDir := hermesDir()
	os.MkdirAll(outDir, 0700)
	keyPath := filepath.Join(outDir, certName)
	certPath := filepath.Join(outDir, certName+"-cert.pub")

	os.WriteFile(keyPath, []byte(result["ssh_private_key"].(string)), 0600)
	os.WriteFile(certPath, []byte(result["ssh_cert"].(string)), 0644)

	fmt.Printf("✅ 证书已保存\n")
	fmt.Printf("   私钥: %s\n", keyPath)
	fmt.Printf("   证书: %s\n", certPath)
	if s, ok := result["serial"]; ok { fmt.Printf("   序列号: %v\n", s) }
	if e, ok := result["expires_at"]; ok { fmt.Printf("   过期:   %v\n", e) }
}

// ---- ssh ----------------------------------------------------------------

func cmdSSH(args []string) {
	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "用法: cert-operator ssh <host> <user> <key> [command]\n")
		os.Exit(1)
	}
	host := args[0]
	user := args[1]
	keyPath := args[2]
	var command string
	if len(args) > 3 { command = args[3] }

	flags := parseFlags(args[4:])
	port := flags["--port"]
	if port == "" { port = "22" }
	expiresAt := flags["--expires-at"]

	// Check cert exists
	certFile := keyPath + "-cert.pub"
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌ 私钥不存在: %s\n", keyPath)
		os.Exit(1)
	}
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌ 证书不存在: %s\n请先运行 cert-operator get-cert\n", certFile)
		os.Exit(1)
	}

	// Check expiry
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err == nil && time.Now().UTC().After(t) {
			fmt.Fprintf(os.Stderr, "❌ 证书已于 %s 过期，请重新获取\n", t.Local().Format("2006-01-02 15:04:05"))
			os.Exit(1)
		}
	}

	// Load cert into SSH agent and enable forwarding for cert-sudo-check
	cleanupAgent := tryAddToAgent(keyPath)
	if cleanupAgent != nil {
		defer cleanupAgent()
	}

	sshArgs := []string{
		"-i", keyPath,
		"-p", port,
		"-A",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", fmt.Sprintf("ConnectTimeout=%d", 15),
		fmt.Sprintf("%s@%s", user, host),
	}
	// sudo -n 拦截由目标服务器上的 /usr/bin/sudo wrapper 处理
	// （通过 deploy-sudo-wrapper.sh 部署，无需客户端 mount namespace）
	if command != "" {
		sshArgs = append(sshArgs, command)
	}

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "❌ SSH 执行失败: %v\n", err)
		os.Exit(1)
	}
}

// ---- deploy -------------------------------------------------------------

func cmdDeploy(args []string) {
	script := "./deploy.sh"
	if len(args) > 0 { script = args[0] }

	if _, err := os.Stat(script); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌ 部署脚本不存在: %s\n", script)
		fmt.Fprintf(os.Stderr, "   请从 CA 服务器获取: scp user@ca-server:~/deploy.sh .\n")
		os.Exit(1)
	}

	cmd := exec.Command("bash", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 部署失败 (exit %d)\n", cmd.ProcessState.ExitCode())
		os.Exit(1)
	}
	fmt.Println("✅ 客户端证书部署完成")
}

// ---- helpers ------------------------------------------------------------

func tryAddToAgent(keyPath string) func() {
	// 清除旧 agent 环境变量
	os.Unsetenv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AGENT_PID")

	// 启动新 agent，记录 PID 以便结束后清理
	out, err := exec.Command("ssh-agent", "-s").Output()
	if err != nil {
		return nil
	}
	var agentPID int
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "SSH_AUTH_SOCK=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.SplitN(parts[1], ";", 2)[0], "'\"")
				os.Setenv("SSH_AUTH_SOCK", val)
			}
		}
		if strings.HasPrefix(line, "SSH_AGENT_PID=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				pidStr := strings.TrimSpace(strings.SplitN(parts[1], ";", 2)[0])
				if pid, err := strconv.Atoi(pidStr); err == nil {
					agentPID = pid
				}
			}
		}
	}
	exec.Command("ssh-add", keyPath).Run()

	// 返回清理函数：结束后杀死 agent
	if agentPID > 0 {
		return func() {
			proc, _ := os.FindProcess(agentPID)
			if proc != nil {
				proc.Kill()
			}
			os.Unsetenv("SSH_AUTH_SOCK")
			os.Unsetenv("SSH_AGENT_PID")
		}
	}
	return nil
}

func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[args[i]] = args[i+1]
				i++
			} else {
				flags[args[i]] = "true"
			}
		}
	}
	return flags
}

func isTrue(v interface{}) bool {
	switch v := v.(type) {
	case bool: return v
	case string: return v == "true" || v == "yes"
	default: return false
	}
}
