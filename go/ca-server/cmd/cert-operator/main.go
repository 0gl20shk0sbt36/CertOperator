package main

import (
	"archive/tar"
	"compress/gzip"
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

const VERSION = "3.2.0"

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
	case "info":
		cmdInfo(args)
	case "ssh":
		cmdSSH(args)
	case "deploy":
		cmdDeploy(args)
	case "deploy-client":
		cmdDeployClient(args)
	case "schedule":
		cmdScheduleClient(args)
	case "health":
		cmdHealth(args)
	case "version":
		if len(args) > 0 && args[0] == "--server" {
			if len(args) > 1 {
				cmdServerVersion(args[1])
			} else {
				fmt.Fprintf(os.Stderr, "用法: cert-operator version --server <url>\n")
				os.Exit(1)
			}
		} else {
			fmt.Printf("cert-operator v%s\n", VERSION)
		}
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
  cert-operator deploy [script]                            Deploy client certs (legacy)
  cert-operator deploy-client <package.tar.gz>             Deploy mTLS client cert package
  cert-operator schedule <action> [flags]                  Schedule mgmt (submit/show/replace)
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
	certDir := flags["--cert-dir"]

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

	// 版本号检查：确保服务端与客户端版本一致
	verURL := strings.TrimRight(server, "/") + "/api/version"
	if verResp, verErr := client.Get(verURL); verErr == nil {
		var verData map[string]interface{}
		json.NewDecoder(verResp.Body).Decode(&verData)
		verResp.Body.Close()
		if sv, ok := verData["version"].(string); ok && sv != VERSION {
			fmt.Fprintf(os.Stderr, "❌ 版本不匹配: 服务端 v%s, 客户端 v%s\n", sv, VERSION)
			fmt.Fprintf(os.Stderr, "   请使用相同版本的 cert-operator CLI\n")
			os.Exit(1)
		}
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
	outDir := certDir
	if outDir == "" { outDir = hermesDir() }
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

// ---- info ---------------------------------------------------------------

func cmdInfo(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "用法: cert-operator info <server>\n")
		os.Exit(1)
	}
	server := args[0]
	flags := parseFlags(args[1:])
	caCert := flags["--ca-cert"]
	if caCert == "" { caCert = defaultPath("ca-https-cert.pem") }
	clientCert := flags["--client-cert"]
	if clientCert == "" { clientCert = defaultPath("client.cert") }
	clientKey := flags["--client-key"]
	if clientKey == "" { clientKey = defaultPath("client.key") }

	certPool := x509.NewCertPool()
	caData, _ := os.ReadFile(caCert)
	if caData != nil {
		certPool.AppendCertsFromPEM(caData)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: loadCert(clientCert, clientKey),
			},
		},
		Timeout: 15 * time.Second,
	}

	// 获取服务器信息
	resp, err := client.Get(strings.TrimRight(server, "/") + "/api/info?level=full")
	if err != nil {
		// 回退到基础 info
		resp, err = client.Get(strings.TrimRight(server, "/") + "/api/info")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 获取信息失败: %v\n", err)
			os.Exit(1)
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data interface{}
	json.Unmarshal(body, &data)
	fmt.Println(string(body))
}

func loadCert(certFile, keyFile string) []tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil { return nil }
	return []tls.Certificate{cert}
}

func makeClient(server string, flags map[string]string) *http.Client {
	caCert := flags["--ca-cert"]; if caCert == "" { caCert = defaultPath("ca-https-cert.pem") }
	clientCert := flags["--client-cert"]; if clientCert == "" { clientCert = defaultPath("client.cert") }
	clientKey := flags["--client-key"]; if clientKey == "" { clientKey = defaultPath("client.key") }
	certPool := x509.NewCertPool()
	caData, _ := os.ReadFile(caCert)
	if caData != nil { certPool.AppendCertsFromPEM(caData) }
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool, Certificates: loadCert(clientCert, clientKey)},
		}, Timeout: 15 * time.Second,
	}
}

func cmdHealth(args []string) {
	if len(args) < 1 { fmt.Fprintf(os.Stderr, "用法: cert-operator health <server>\n"); os.Exit(1) }
	flags := parseFlags(args[1:])
	client := makeClient(args[0], flags)
	resp, err := client.Get(strings.TrimRight(args[0], "/") + "/api/health")
	if err != nil { fmt.Fprintf(os.Stderr, "❌ 健康检查失败: %v\n", err); os.Exit(1) }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func cmdServerVersion(server string) {
	client := makeClient(server, parseFlags(nil))
	resp, err := client.Get(strings.TrimRight(server, "/") + "/api/version")
	if err != nil { fmt.Fprintf(os.Stderr, "❌ 获取版本失败: %v\n", err); os.Exit(1) }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
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

// ---- deploy-client --------------------------------------------------------

func cmdDeployClient(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "用法: cert-operator deploy-client <package.tar.gz>\n")
		fmt.Fprintf(os.Stderr, "  解压 mTLS 客户端证书包到 ~/.hermes/certs/\n")
		os.Exit(1)
	}
	tarFile := args[0]

	if _, err := os.Stat(tarFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌ 证书包不存在: %s\n", tarFile)
		os.Exit(1)
	}

	certDir := hermesDir()
	os.MkdirAll(certDir, 0700)

	f, err := os.Open(tarFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 无法打开: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 无法解压缩: %v\n", err)
		os.Exit(1)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ tar 读取错误: %v\n", err)
			os.Exit(1)
		}

		// Prevent path traversal
		name := filepath.Base(hdr.Name)
		dest := filepath.Join(certDir, name)

		switch hdr.Typeflag {
		case tar.TypeReg:
			data, err := io.ReadAll(tr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ 读取 %s: %v\n", hdr.Name, err)
				os.Exit(1)
			}
			var mode os.FileMode = 0644
			if strings.HasSuffix(name, ".key") {
				mode = 0600
			}
			if err := os.WriteFile(dest, data, mode); err != nil {
				fmt.Fprintf(os.Stderr, "❌ 写入 %s: %v\n", dest, err)
				os.Exit(1)
			}
			fmt.Printf("   ✅ %s → %s\n", hdr.Name, dest)
			count++
		}
	}

	if count == 0 {
		fmt.Fprintf(os.Stderr, "❌ 证书包为空\n")
		os.Exit(1)
	}

	fmt.Printf("\n✅ 客户端证书部署完成 (%d 文件)\n", count)
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

// ---- schedule client ------------------------------------------------------

func cmdScheduleClient(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, `Schedule commands:
  schedule submit             Submit a passwordless schedule request
     --server URL             CA server URL
     --rules JSON             Rules JSON: [{"days":[1,3,5],"start_time":"07:00","end_time":"08:00","max_count":10,"group":"admin"}]
  schedule show               Show current request status
     --server URL
  schedule replace            Replace existing pending request
     --server URL
     --rules JSON
  schedule show-approved       Show own approved rules
     --server URL
  schedule revoke             Revoke own approved rules
     --server URL
`)
		os.Exit(1)
	}

	action := args[0]
	flags := parseFlags(args[1:])

	server := flags["--server"]
	if server == "" {
		fmt.Fprintf(os.Stderr, "❌ --server is required\n")
		os.Exit(1)
	}
	rulesJSON := flags["--rules"]

	switch action {
	case "submit":
		client := makeClient(server, flags)
		body := fmt.Sprintf(`{"rules":%s}`, rulesJSON)
		resp, err := client.Post(strings.TrimRight(server, "/")+"/api/schedule/request", "application/json", strings.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))

	case "show":
		client := makeClient(server, flags)
		resp, err := client.Get(strings.TrimRight(server, "/") + "/api/schedule/requests")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))

	case "replace":
		client := makeClient(server, flags)
		body := fmt.Sprintf(`{"rules":%s}`, rulesJSON)
		req, err := http.NewRequest(http.MethodPut, strings.TrimRight(server, "/")+"/api/schedule/replace", strings.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))

	case "show-approved":
		client := makeClient(server, flags)
		resp, err := client.Get(strings.TrimRight(server, "/") + "/api/schedule/approved")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))

	case "revoke":
		client := makeClient(server, flags)
		req, err := http.NewRequest(http.MethodDelete, strings.TrimRight(server, "/")+"/api/schedule/approved", nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))

	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown action: %s\n", action)
		os.Exit(1)
	}
}
