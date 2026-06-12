// cert-operator v2 — TOTP-gated SSH certificate authority.
//
// Subcommands:
//
//	init                        Initialize CA (keys, HTTPS cert, client cert, deploy script)
//	serve [flags]               Start HTTPS API server
//	pubkey                      Show CA public key
//	totp [flags]                Configure/manage TOTP for default group
//	groups ACTION [args...]     Group management (list, create, delete, users, totp, config)
//	renew-cert                  Regenerate HTTPS certificate
//	version                     Show version
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cert-operator/ca-server/v2/internal/ca"
	"github.com/cert-operator/ca-server/v2/internal/config"
	"github.com/cert-operator/ca-server/v2/internal/server"
	"github.com/cert-operator/ca-server/v2/internal/totp"
)

var versionStr = server.Version()

var configPath string

func init() {
	// Default config path: config.json in the same directory as the binary.
	if cp := os.Getenv("CA_SERVER_CONFIG"); cp != "" {
		configPath = cp
	} else {
		configPath = "config.json"
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "help":
		printUsage()
		os.Exit(0)
	case "init":
		cmdInit()
	case "serve":
		cmdServe(args)
	case "pubkey":
		cmdPubkey()
	case "totp":
		cmdTOTP(args)
	case "users":
		cmdUsers(args)
	case "groups":
		cmdGroups(args)
	case "clients":
		cmdClients(args)
	case "renew-cert":
		cmdRenewCert(args)
	case "reset":
		cmdReset(args)
	case "version":
		fmt.Printf("cert-operator v%s\n", versionStr)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `cert-operator v%s — TOTP-gated SSH certificate authority

Usage:
  ca-server [command] [flags]
  ca-server --help         Show this help
  ca-server --version      Show version

Commands:
  init                     Initialize CA (keys, HTTPS cert, mTLS CA, admin client)
  serve [flags]            Start HTTPS API server
  pubkey                   Show CA public key
  totp [--verify|--regenerate]  TOTP management (default group)
  groups [action] [args]   Group management (see "groups --help")
  clients [action] [args]  mTLS client cert management (issue/list/revoke/show)
  renew-cert               Regenerate HTTPS certificate
  reset <mode>             Reset components (ca|https|client|totp <grp>|group <grp>|all)
  version                  Show version

Use "ca-server <command> --help" for more information.
`, versionStr)
}

func printGroupsHelp() {
	fmt.Fprintf(os.Stderr, `cert-operator v%s — Group management

Usage:
  ca-server groups list                                       List all groups
  ca-server groups create <name>                              Create a group
  ca-server groups delete <name>                              Delete a group
  ca-server groups users <name> list                          List group users
  ca-server groups users <name> add <user,...>                Add users
  ca-server groups users <name> remove <user,...>             Remove users
  ca-server groups totp <name> set                            Generate TOTP secret
  ca-server groups totp <name> verify                         Show current TOTP code
  ca-server groups config <name> get [key]                    Get group config
  ca-server groups config <name> set <key> <value>            Set group config

Keys for "config set": sudo, frozen, validity-minutes, parent, allowed-users
`, versionStr)
}

func _legacy_printUsage() {
	fmt.Fprintf(os.Stderr, `cert-operator v%s — TOTP-gated SSH certificate authority

Usage:
  ca-server init                          Initialize CA
  ca-server serve [flags]                 Start HTTPS API server
  ca-server pubkey                        Show CA public key
  ca-server totp [--verify] [--regenerate]  TOTP management (default group)
  ca-server groups ACTION [args...]       Group management
  ca-server renew-cert                    Regenerate HTTPS certificate
  ca-server version                       Show version

Groups subcommands:
  groups list                              List all groups
  groups create <name>                     Create a group
  groups delete <name>                     Delete a group
  groups users <name> list                 List group users
  groups users <name> add <user,...>       Add users
  groups users <name> remove <user,...>    Remove users
  groups totp <name> set                   Generate TOTP secret for group
  groups totp <name> verify                Show current TOTP code
  groups config <name> get [key]           Get group config
  groups config <name> set <key> <value>   Set group config

Serve flags:
  --host HOST     Listen address (default: config.yaml or 0.0.0.0)
  --port PORT     Listen port (default: config.yaml or 8443)
  --no-mtls       Disable mTLS (default: enabled)
  --debug         Enable debug logging
`, versionStr)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func cmdInit() {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := ca.Init(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Init failed: %v\n", err)
		os.Exit(1)
	}

	// Create default group
	ensureDefaultGroup(cfg)
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	host := fs.String("host", "", "Listen address")
	port := fs.Int("port", 0, "Listen port")
	noMtls := fs.Bool("no-mtls", false, "Disable mTLS")
	debug := fs.Bool("debug", false, "Enable debug logging")
	fs.Parse(args)

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Migrate old global config to default group
	ensureDefaultGroup(cfg)
	cfg, _ = config.Load(configPath) // re-read after migration

	caKey, caPub := ca.KeyPaths(cfg)
	if _, err := os.Stat(caKey); err != nil {
		fmt.Fprintf(os.Stderr, "❌ CA key not found — run init first\n")
		os.Exit(1)
	}
	httpsKey := ca.HTTPSKeyPath(cfg)
	httpsCert := ca.HTTPSCertPath(cfg)
	if _, err := os.Stat(httpsKey); err != nil || stat(httpsCert) != nil {
		fmt.Fprintf(os.Stderr, "❌ HTTPS cert not found — run init first\n")
		os.Exit(1)
	}

	if !*noMtls {
		mtlsCACert := ca.MTLSCACertPath(cfg)
		if stat(mtlsCACert) != nil {
			fmt.Fprintf(os.Stderr, "❌ mTLS CA cert not found — re-run init or use --no-mtls\n")
			os.Exit(1)
		}
	}

	srv := &server.Server{
		ConfigPath:     configPath,
		NoMTLS:         *noMtls,
		CAKeyPath:      caKey,
		CAKeyPubPath:   caPub,
		HTTPSCertPath:  httpsCert,
		HTTPSKeyPath:   httpsKey,
		ClientCertPath: ca.MTLSCACertPath(cfg),
	}

	// Override host/port from flags
	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != 0 {
		cfg.Server.Port = *port
	}
	_ = debug // reserved for future use

	if err := srv.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Server error: %v\n", err)
		os.Exit(1)
	}
}

func stat(p string) error {
	_, err := os.Stat(p)
	return err
}

// ---------------------------------------------------------------------------
// pubkey
// ---------------------------------------------------------------------------

func cmdPubkey() {
	pk, err := ca.Pubkey(mustLoadConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🔑 CA public key:")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(pk)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
	fmt.Println("📋 Target server configuration commands:")
	fmt.Println()
	cfg, _ := config.Load(configPath)
	caPubPath := filepath.Join(ca.DataDir(cfg), "ca_key.pub")
	fmt.Printf("  # 1. Copy CA public key\n")
	fmt.Printf("  scp %s root@target-server:/etc/ssh/ca_key.pub\n", caPubPath)
	fmt.Println()
	fmt.Printf("  # 2. Edit /etc/ssh/sshd_config and add:\n")
	fmt.Printf("  TrustedUserCAKeys /etc/ssh/ca_key.pub\n")
	fmt.Println()
	fmt.Printf("  # 3. Restart SSH service\n")
	fmt.Printf("  sudo systemctl restart sshd\n")
	fmt.Println()
	fmt.Printf("  # 4. Verify\n")
	fmt.Printf("  sudo sshd -T | grep trust\n")
}

// LoadOrExit is a convenience helper used by several subcommands.
func mustLoadConfig() *config.Config {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// totp — TOTP management for the default group
// ---------------------------------------------------------------------------

func cmdTOTP(args []string) {
	fs := flag.NewFlagSet("totp", flag.ExitOnError)
	verify := fs.Bool("verify", false, "Show current TOTP code")
	regenerate := fs.Bool("regenerate", false, "Regenerate TOTP secret")
	fs.Parse(args)

	cfg := mustLoadConfig()
	ensureDefaultGroup(cfg)
	cfg = mustLoadConfig() // re-read

	dg := cfg.Groups["default"]

	issuer := cfg.TOTP.Issuer
	if issuer == "" {
		issuer = "CertOperator"
	}
	account := cfg.TOTP.Account
	if account == "" {
		account = "admin"
	}

	if *regenerate || dg.TOTPSecret == "" {
		secret := totp.GenerateSecret()
		dg.TOTPSecret = secret
		cfg.Groups["default"] = dg
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to save config: %v\n", err)
			os.Exit(1)
		}
		if *regenerate {
			fmt.Println("🔄 TOTP secret regenerated (default group)")
		} else {
			fmt.Println("🔐 Generated new TOTP secret (default group)")
		}
	} else {
		fmt.Println("🔐 Current TOTP configuration (default group)")
	}

	secret := dg.TOTPSecret
	fmt.Println()
	fmt.Printf("  Issuer : %s\n", issuer)
	fmt.Printf("  Account: %s\n", account)
	fmt.Printf("  Secret : %s\n", secret)
	fmt.Println()

	uri := totp.GenerateURI(secret, issuer, account)
	fmt.Printf("💡 Scan this URI with your authenticator app:\n")
	fmt.Printf("   %s\n", uri)
	fmt.Println()

	if *verify {
		code := totp.Now(secret)
		fmt.Printf("✅ Current TOTP code: %s\n", code)
		fmt.Println("   Compare with your authenticator app to confirm")
	} else {
		fmt.Printf("💡 Run 'ca-server totp --verify' to test the current TOTP code\n")
	}
}

// ---------------------------------------------------------------------------
// users — manage allowed_users list for the default group
// ---------------------------------------------------------------------------

func cmdUsers(args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}

	action := args[0]
	rest := args[1:]

	cfg := mustLoadConfig()
	ensureDefaultGroup(cfg)
	cfg = mustLoadConfig()

	dg := cfg.Groups["default"]
	allowed := splitUserSet(dg.AllowedUsers)

	switch action {
	case "list":
		fmt.Println("🔑 Allowed users (default group):")
		if len(allowed) == 0 {
			fmt.Println("  (none)")
		} else {
			users := sortedKeys(allowed)
			for _, u := range users {
				fmt.Printf("  - %s\n", u)
			}
		}
	case "add":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "❌ Please specify user(s) to add\n")
			os.Exit(1)
		}
		for _, u := range splitUsers(strings.Join(rest, ",")) {
			if u != "" {
				allowed[u] = struct{}{}
			}
		}
		dg.AllowedUsers = joinSorted(allowed)
		cfg.Groups["default"] = dg
		cfg.Save()
		fmt.Printf("✅ Updated allowed users: %s\n", dg.AllowedUsers)
	case "remove":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "❌ Please specify user(s) to remove\n")
			os.Exit(1)
		}
		for _, u := range splitUsers(strings.Join(rest, ",")) {
			delete(allowed, u)
		}
		dg.AllowedUsers = joinSorted(allowed)
		cfg.Groups["default"] = dg
		cfg.Save()
		fmt.Printf("✅ Updated allowed users: %s\n", dg.AllowedUsers)
	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown action: %s (use list, add, or remove)\n", action)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// groups — group-level management
// ---------------------------------------------------------------------------

func cmdGroups(args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	if args[0] == "--help" || args[0] == "-h" {
		printGroupsHelp()
		return
	}

	action := args[0]
	rest := args[1:]

	cfg := mustLoadConfig()
	groups := cfg.Groups
	if groups == nil {
		groups = make(map[string]config.GroupConfig)
		cfg.Groups = groups
	}

	switch action {
	case "list":
		fmt.Println("📁 Groups:")
		if len(groups) == 0 {
			fmt.Println("  (none)")
			return
		}
		for _, gname := range sortedGroupNames(groups) {
			gcfg := groups[gname]
			au := gcfg.AllowedUsers
			vh := gcfg.ValidityMinutes
			if vh <= 0 {
				vh = cfg.CA.ValidityMinutes
				if vh <= 0 {
					vh = 60
				}
			}
			parent := gcfg.Parent
			label := gname
			if parent != "" {
				label = fmt.Sprintf("%s → %s", gname, parent)
			}
			fmt.Printf("  📁 %s\n", label)
			if parent != "" {
				resolved := cfg.ResolveGroup(gname)
				if resolved != nil {
					fmt.Printf("     Inherited users: %s\n", orEmpty(resolved.AllowedUsers))
				}
			} else {
				fmt.Printf("     Allowed users:   %s\n", orEmpty(au))
			}
			fmt.Printf("     Validity:        %d min\n", vh)
			if gcfg.TOTPSecret != "" {
				fmt.Printf("     TOTP:            ✅\n")
			} else {
				fmt.Printf("     TOTP:            ❌\n")
			}
			if gcfg.IsFrozen() {
				fmt.Printf("     ❄ Frozen\n")
			}
			// Resolve extensions
			exts := gcfg.Extensions
			if parent != "" {
				if r := cfg.ResolveGroup(gname); r != nil {
					exts = r.Extensions
				}
			}
			if exts != nil && exts["sudo"] != "" {
				fmt.Printf("     sudo:            ✅ allowed\n")
			} else {
				fmt.Printf("     sudo:            ❌ not allowed\n")
			}
		}

	case "create":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "❌ Please specify group name\n")
			os.Exit(1)
		}
		gname := rest[0]
		if _, ok := groups[gname]; ok {
			fmt.Fprintf(os.Stderr, "❌ Group %s already exists\n", gname)
			os.Exit(1)
		}
		groups[gname] = config.GroupConfig{
			AllowedUsers:    "",
			ValidityMinutes: 60,
			Parent:          "",
			Extensions:      map[string]string{},
		}
		cfg.Groups = groups
		cfg.Save()
		fmt.Printf("✅ Group %s created\n", gname)

	case "delete":
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "❌ Please specify group name\n")
			os.Exit(1)
		}
		gname := rest[0]
		if _, ok := groups[gname]; !ok {
			fmt.Fprintf(os.Stderr, "❌ Group %s does not exist\n", gname)
			os.Exit(1)
		}
		delete(groups, gname)
		cfg.Groups = groups
		cfg.Save()
		fmt.Printf("✅ Group %s deleted\n", gname)

	case "users":
		if len(rest) < 2 {
			fmt.Fprintf(os.Stderr, "❌ Usage: groups users <name> list|add|remove [user,...]\n")
			os.Exit(1)
		}
		gname := rest[0]
		subAction := rest[1]
		subRest := rest[2:]

		gcfg, ok := groups[gname]
		if !ok {
			fmt.Fprintf(os.Stderr, "❌ Group %s does not exist — use 'groups create %s' first\n", gname, gname)
			os.Exit(1)
		}

		allowed := splitUserSet(gcfg.AllowedUsers)

		switch subAction {
		case "list":
			fmt.Printf("📁 %s users: %s\n", gname, orEmpty(gcfg.AllowedUsers))
		case "add":
			if len(subRest) == 0 {
				fmt.Fprintf(os.Stderr, "❌ Please specify user(s) to add\n")
				os.Exit(1)
			}
			for _, u := range splitUsers(strings.Join(subRest, ",")) {
				if u != "" {
					allowed[u] = struct{}{}
				}
			}
			gcfg.AllowedUsers = joinSorted(allowed)
			groups[gname] = gcfg
			cfg.Groups = groups
			cfg.Save()
			fmt.Printf("✅ %s users updated: %s\n", gname, gcfg.AllowedUsers)
		case "remove":
			if len(subRest) == 0 {
				fmt.Fprintf(os.Stderr, "❌ Please specify user(s) to remove\n")
				os.Exit(1)
			}
			for _, u := range splitUsers(strings.Join(subRest, ",")) {
				delete(allowed, u)
			}
			gcfg.AllowedUsers = joinSorted(allowed)
			groups[gname] = gcfg
			cfg.Groups = groups
			cfg.Save()
			fmt.Printf("✅ %s users updated: %s\n", gname, gcfg.AllowedUsers)
		default:
			fmt.Fprintf(os.Stderr, "❌ Unknown sub-action: %s (use list, add, or remove)\n", subAction)
			os.Exit(1)
		}

	case "totp":
		if len(rest) < 2 {
			fmt.Fprintf(os.Stderr, "❌ Usage: groups totp <name> set|verify\n")
			os.Exit(1)
		}
		gname := rest[0]
		subAction := rest[1]

		gcfg, ok := groups[gname]
		if !ok {
			fmt.Fprintf(os.Stderr, "❌ Group %s does not exist\n", gname)
			os.Exit(1)
		}

		issuer := cfg.TOTP.Issuer
		if issuer == "" {
			issuer = "CertOperator"
		}
		account := fmt.Sprintf("%s-%s", gname, cfg.TOTP.Account)

		switch subAction {
		case "set":
			secret := totp.GenerateSecret()
			gcfg.TOTPSecret = secret
			groups[gname] = gcfg
			cfg.Groups = groups
			cfg.Save()

			uri := totp.GenerateURI(secret, issuer, account)
			fmt.Printf("🔐 %s TOTP configured\n", gname)
			fmt.Printf("   Secret: %s\n", secret)
			fmt.Printf("   URI:    %s\n", uri)
		case "verify":
			secret := gcfg.TOTPSecret
			if secret == "" {
				fmt.Fprintf(os.Stderr, "❌ %s has no TOTP configured\n", gname)
				os.Exit(1)
			}
			code := totp.Now(secret)
			fmt.Printf("🔐 %s current TOTP code: %s\n", gname, code)
		default:
			fmt.Fprintf(os.Stderr, "❌ Unknown sub-action: %s (use set or verify)\n", subAction)
			os.Exit(1)
		}

	case "config":
		if len(rest) < 2 {
			fmt.Fprintf(os.Stderr, "❌ Usage: groups config <name> get [key] | set <key> <value>\n")
			os.Exit(1)
		}
		gname := rest[0]
		subAction := rest[1]
		subRest := rest[2:]

		gcfg, ok := groups[gname]
		if !ok {
			fmt.Fprintf(os.Stderr, "❌ Group %s does not exist\n", gname)
			os.Exit(1)
		}

		switch subAction {
		case "get":
			key := ""
			if len(subRest) > 0 {
				key = subRest[0]
			}
			if key == "" {
				fmt.Printf("📁 %s config:\n", gname)
				fmt.Printf("   allowed-users:    %s\n", orEmpty(gcfg.AllowedUsers))
				fmt.Printf("   validity-minutes: %d\n", gcfg.ValidityMinutes)
				fmt.Printf("   parent:           %s\n", orEmpty(gcfg.Parent))
				fmt.Printf("   frozen:           %v\n", gcfg.IsFrozen())
				sudo := "disabled"
				if gcfg.Extensions != nil && gcfg.Extensions["sudo"] != "" {
					sudo = "enabled"
				}
				fmt.Printf("   sudo:             %s\n", sudo)
			} else {
				switch key {
				case "allowed-users", "allowed_users":
					fmt.Println(orEmpty(gcfg.AllowedUsers))
				case "validity-minutes", "validity_minutes":
					fmt.Println(gcfg.ValidityMinutes)
				case "parent":
					fmt.Println(orEmpty(gcfg.Parent))
				case "frozen":
					fmt.Println(gcfg.Frozen)
				case "sudo":
					if gcfg.Extensions != nil && gcfg.Extensions["sudo"] != "" {
						fmt.Println("enabled")
					} else {
						fmt.Println("disabled")
					}
				default:
					fmt.Fprintf(os.Stderr, "❌ Unknown key: %s (available: sudo frozen validity-minutes parent allowed-users)\n", key)
					os.Exit(1)
				}
			}
		case "set":
			if len(subRest) < 2 {
				fmt.Fprintf(os.Stderr, "❌ Usage: groups config <name> set <key> <value>\n")
				os.Exit(1)
			}
			key := subRest[0]
			val := subRest[1]

			switch key {
			case "sudo":
				if gcfg.Extensions == nil {
					gcfg.Extensions = map[string]string{}
				}
				if val == "true" || val == "yes" || val == "1" || val == "enabled" {
					gcfg.Extensions["sudo"] = "true"
				} else {
					delete(gcfg.Extensions, "sudo")
				}
				fmt.Printf("✅ %s sudo = %s\n", gname, val)
			case "frozen":
				v := strings.ToLower(val)
				gcfg.Frozen = v == "true" || v == "yes" || v == "1"
				fmt.Printf("✅ %s frozen = %v\n", gname, gcfg.Frozen)
			case "validity-minutes", "validity_minutes":
				var minutes int
				if _, err := fmt.Sscanf(val, "%d", &minutes); err != nil {
					fmt.Fprintf(os.Stderr, "❌ Invalid value for validity-minutes: %s\n", val)
					os.Exit(1)
				}
				gcfg.ValidityMinutes = minutes
				fmt.Printf("✅ %s validity-minutes = %d\n", gname, minutes)
			case "parent":
				if val == "none" {
					gcfg.Parent = ""
				} else {
					gcfg.Parent = val
				}
				fmt.Printf("✅ %s parent = %s\n", gname, orEmpty(gcfg.Parent))
			case "allowed-users", "allowed_users":
				gcfg.AllowedUsers = val
				fmt.Printf("✅ %s allowed-users = %s\n", gname, val)
			default:
				fmt.Fprintf(os.Stderr, "❌ Unknown key: %s (available: sudo frozen validity-minutes parent allowed-users)\n", key)
				os.Exit(1)
			}
			groups[gname] = gcfg
			cfg.Groups = groups
			cfg.Save()
		default:
			fmt.Fprintf(os.Stderr, "❌ Unknown sub-action: %s (use get or set)\n", subAction)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown action: %s\n", action)
		fmt.Fprintf(os.Stderr, "   Available: list create delete users totp config\n")
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// clients — mTLS client certificate lifecycle
// ---------------------------------------------------------------------------

func cmdClients(args []string) {
	if len(args) == 0 {
		printClientsHelp()
		os.Exit(1)
	}

	action := args[0]
	rest := args[1:]
	cfg := mustLoadConfig()

	switch action {
	case "issue":
		cmdClientsIssue(cfg, rest)
	case "revoke":
		if len(rest) < 1 {
			fmt.Fprintf(os.Stderr, "❌ Usage: ca-server clients revoke <name>\n")
			os.Exit(1)
		}
		if err := ca.RevokeClientCert(cfg, rest[0]); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
	case "list":
		records, err := ca.ListClientCerts(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		if len(records) == 0 {
			fmt.Println("(no clients issued)")
		} else {
			for _, r := range records {
				fmt.Printf("📋 %s\n", r.Name)
				fmt.Printf("   Granted to: %s\n", r.GrantedTo)
				fmt.Printf("   Serial:     %d\n", r.Serial)
				fmt.Printf("   Expires:    %s\n", r.ExpiresAt)
				if r.SAN != "" {
					fmt.Printf("   SAN:        %s\n", r.SAN)
				}
				if r.User != "" {
					fmt.Printf("   User:       %s\n", r.User)
				}
				fmt.Println()
			}
		}
	case "show":
		if len(rest) < 1 {
			fmt.Fprintf(os.Stderr, "❌ Usage: ca-server clients show <name>\n")
			os.Exit(1)
		}
		r, err := ca.GetClientCert(cfg, rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("📋 %s\n", r.Name)
		fmt.Printf("   Granted to:  %s\n", r.GrantedTo)
		fmt.Printf("   Serial:      %d\n", r.Serial)
		fmt.Printf("   Issued:      %s\n", r.IssuedAt)
		fmt.Printf("   Expires:     %s\n", r.ExpiresAt)
		if r.SAN != "" {
			fmt.Printf("   SAN:         %s\n", r.SAN)
		}
		if r.User != "" {
			fmt.Printf("   User:        %s\n", r.User)
		}
		fmt.Printf("   Cert file:   %s\n", r.CertFile)
	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown action: %s\n", action)
		printClientsHelp()
		os.Exit(1)
	}
}

func cmdClientsIssue(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("clients-issue", flag.ExitOnError)
	validity := fs.Int("validity", 365, "Validity in days")
	san := fs.String("san", "", "SAN: DNS:x,IP:y")
	user := fs.String("user", "", "SSH user name")
	fs.Parse(args)
	pos := fs.Args()

	if len(pos) < 2 {
		fmt.Fprintf(os.Stderr, "❌ Usage: ca-server clients issue <name> <granted-to> [--validity DAYS] [--san DNS:x,IP:y] [--user NAME]\n")
		os.Exit(1)
	}

	tarPath, err := ca.IssueClientCert(cfg, pos[0], pos[1], *validity, strings.TrimSpace(*san), strings.TrimSpace(*user))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Issue failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n📦 Package ready: %s\n", tarPath)
	fmt.Println("   Deploy to client: scp <this-package> user@client:/tmp/ && tar -xzf /tmp/<pkg> -C ~/.hermes/certs/")
}

func printClientsHelp() {
	fmt.Fprintf(os.Stderr, `Client certificate management:

Usage:
  ca-server clients issue <name> <granted-to> [flags]   Issue client mTLS cert
  ca-server clients list                                  List all issued clients
  ca-server clients show <name>                           Show client details
  ca-server clients revoke <name>                         Revoke (remove from roster)

Issue flags:
  --validity DAYS    Validity in days (default 365)
  --san DNS:x,IP:y   Optional Subject Alternative Names
  --user NAME        Associated SSH user name
`)
}

// ---------------------------------------------------------------------------
// renew-cert
// ---------------------------------------------------------------------------

func cmdRenewCert(args []string) {
	sanArg := ""
	for i, a := range args {
		if a == "--san" && i+1 < len(args) {
			sanArg = args[i+1]
		}
	}
	cfg := mustLoadConfig()
	if sanArg != "" {
		// 更新配置文件中的 SAN
		fmt.Printf("   SAN: %s\n", sanArg)
		cfg.Server.SAN = sanArg
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ 保存配置失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("   ✅ config.json 已更新")
	}
	if err := ca.RenewCert(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   ⚠️  客户端需重新运行 deploy.sh 获取新证书")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ensureDefaultGroup(cfg *config.Config) {
	if cfg.Groups == nil {
		cfg.Groups = make(map[string]config.GroupConfig)
	}
	if _, ok := cfg.Groups["default"]; !ok {
		cfg.Groups["default"] = config.GroupConfig{
			ValidityMinutes: cfg.CA.ValidityMinutes,
		}
	}
	dg := cfg.Groups["default"]
	changed := false

	// v2 has no global allowed_users — everything goes through groups
	if dg.ValidityMinutes <= 0 {
		dg.ValidityMinutes = cfg.CA.ValidityMinutes
		if dg.ValidityMinutes <= 0 {
			dg.ValidityMinutes = 60
		}
		changed = true
	}
	if changed {
		cfg.Groups["default"] = dg
		cfg.Save()
	}
}

func splitUsers(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

func splitUserSet(s string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, u := range splitUsers(s) {
		if u != "" {
			set[u] = struct{}{}
		}
	}
	return set
}

func joinSorted(set map[string]struct{}) string {
	users := sortedKeys(set)
	return strings.Join(users, ",")
}

func sortedKeys(set map[string]struct{}) []string {
	users := make([]string, 0, len(set))
	for u := range set {
		users = append(users, u)
	}
	// Simple sort
	for i := 0; i < len(users); i++ {
		for j := i + 1; j < len(users); j++ {
			if users[i] > users[j] {
				users[i], users[j] = users[j], users[i]
			}
		}
	}
	return users
}

func sortedGroupNames(groups map[string]config.GroupConfig) []string {
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

func orEmpty(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

func cmdReset(args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stderr, "Usage: ca-server reset <mode> [args]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Modes:")
		fmt.Fprintln(os.Stderr, "  ca              Regenerate CA key pair (invalidates all SSH certs!)")
		fmt.Fprintln(os.Stderr, "  https           Regenerate HTTPS/TLS certificate")
		fmt.Fprintln(os.Stderr, "  client          Regenerate mTLS client cert + deploy.sh")
		fmt.Fprintln(os.Stderr, "  totp <group>    Reset TOTP secret for a group")
		fmt.Fprintln(os.Stderr, "  group <name>    Reset group config to empty defaults")
		fmt.Fprintln(os.Stderr, "  all             Full re-init (deletes everything!)")
		return
	}

	cfg := mustLoadConfig()

	switch args[0] {
	case "ca":
		if err := ca.ResetCA(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Reset CA failed: %v\n", err)
			os.Exit(1)
		}
	case "https":
		if err := ca.ResetHTTPS(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Reset HTTPS failed: %v\n", err)
			os.Exit(1)
		}
		// Also update deploy.sh since HTTPS cert changed
		if err := ca.ResetClient(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Update deploy.sh failed: %v\n", err)
			os.Exit(1)
		}
	case "client":
		if err := ca.ResetClient(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Reset client failed: %v\n", err)
			os.Exit(1)
		}
	case "totp":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: ca-server reset totp <group-name>")
			os.Exit(1)
		}
		groupName := args[1]
		if _, ok := cfg.Groups[groupName]; !ok {
			fmt.Fprintf(os.Stderr, "❌ Group '%s' not found\n", groupName)
			os.Exit(1)
		}
		secret := totp.GenerateSecret()
		g := cfg.Groups[groupName]
		g.TOTPSecret = secret
		cfg.Groups[groupName] = g
		_ = cfg.Save()
		fmt.Printf("✅ TOTP secret reset for group '%s'\n", groupName)
		fmt.Printf("   Secret: %s\n", secret)
		fmt.Printf("   Now  : %s\n", totp.Now(secret))
	case "group":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: ca-server reset group <group-name>")
			os.Exit(1)
		}
		groupName := args[1]
		g, ok := cfg.Groups[groupName]
		if !ok {
			fmt.Fprintf(os.Stderr, "❌ Group '%s' not found\n", groupName)
			os.Exit(1)
		}
		g.AllowedUsers = ""
		g.ValidityMinutes = 0
		g.Frozen = nil
		g.Parent = ""
		g.Extensions = nil
		// Keep TOTP secret (use reset totp to regenerate)
		cfg.Groups[groupName] = g
		_ = cfg.Save()
		fmt.Printf("✅ Group '%s' config reset to defaults (TOTP secret kept)\n", groupName)
	case "all":
		fmt.Println("⚠️  This will DELETE all data and re-initialize!")
		fmt.Println("    All issued SSH certs will be invalidated.")
		fmt.Println("    All TOTP secrets will be regenerated.")
		fmt.Println("    All groups will be cleared.")
		fmt.Print("    Continue? (yes/no): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "yes" {
			fmt.Println("Cancelled.")
			return
		}
		if err := ca.ResetAll(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Reset all failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown reset mode: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Valid modes: ca, https, client, totp <group>, group <name>, all")
		os.Exit(1)
	}
}