package check

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	defaultWeakPasswords = map[string]bool{
		"123456":   true,
		"password": true,
		"admin":    true,
		"root":     true,
		"12345678": true,
	}
	weakPasswords = copyMap(defaultWeakPasswords)
	weakPassMutex sync.RWMutex

	reRequirepass = regexp.MustCompile(`^requirepass\s+(\S+)`)
	reMasterauth  = regexp.MustCompile(`^masterauth\s+(\S+)`)
	reMysqlPass   = regexp.MustCompile(`^password\s*=\s*(\S+)`)
)

func copyMap(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

type ProcessInfo struct {
	Pid     string
	Name    string
	Cmdline string
	Cwd     string
}

func findProcesses(pattern string) ([]ProcessInfo, error) {
	var procs []ProcessInfo
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(pattern)

	for _, f := range entries {
		if !f.IsDir() || !isNumeric(f.Name()) {
			continue
		}
		pid := f.Name()
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

		exePath, _ := os.Readlink(filepath.Join("/proc", pid, "exe"))

		if re.MatchString(cmdline) || re.MatchString(exePath) {
			cwd, _ := os.Readlink(filepath.Join("/proc", pid, "cwd"))
			procs = append(procs, ProcessInfo{
				Pid:     pid,
				Name:    filepath.Base(exePath),
				Cmdline: cmdline,
				Cwd:     cwd,
			})
		}
	}
	return procs, nil
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func findConfigFile(proc ProcessInfo, argFlag string, defaultPaths []string) string {
	if argFlag != "" {
		re := regexp.MustCompile(argFlag + `\s*=?\s*(\S+)`)
		matches := re.FindStringSubmatch(proc.Cmdline)
		if len(matches) > 1 {
			return matches[1]
		}
	} else {
		parts := strings.Fields(proc.Cmdline)
		for i, part := range parts {
			if i == 0 {
				continue
			}
			if strings.HasPrefix(part, "-") {
				continue
			}
			ext := filepath.Ext(part)
			switch ext {
			case ".conf", ".ini", ".properties", ".xml", ".yaml", ".yml":
				return part
			}
		}
	}

	rootPath := filepath.Join("/proc", proc.Pid, "root")
	for _, p := range defaultPaths {
		fullPath := filepath.Join(rootPath, p)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}
	return ""
}

func readProperties(path string) (map[string]string, error) {
	props := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			props[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return props, nil
}

// UpdateWeakPassDict replaces the entire weak password dictionary (full sync from server).
func UpdateWeakPassDict(passwords []string) {
	weakPassMutex.Lock()
	defer weakPassMutex.Unlock()
	newDict := copyMap(defaultWeakPasswords)
	for _, p := range passwords {
		p = strings.TrimSpace(p)
		if p != "" {
			newDict[p] = true
		}
	}
	weakPasswords = newDict
}

func isWeakPassword(pass string) bool {
	weakPassMutex.RLock()
	defer weakPassMutex.RUnlock()
	return weakPasswords[pass]
}

// collectRisks collects all risk messages into a single error string.
// Returns true (pass) if no risks, false with combined error if risks found.
func collectRisks(risks []string) (bool, error) {
	if len(risks) == 0 {
		return true, nil
	}
	return false, fmt.Errorf("%s", strings.Join(risks, "; "))
}

// --- Nacos shared helper ---

func findNacosHomeAndProps(proc ProcessInfo) (homeDir string, props map[string]string, ok bool) {
	confPath := findConfigFile(proc, "-Dnacos.home", nil)
	if confPath != "" {
		homeDir = confPath
		confPath = filepath.Join(confPath, "conf", "application.properties")
	} else {
		homeDir = proc.Cwd
		confPath = filepath.Join(proc.Cwd, "conf", "application.properties")
	}

	if _, err := os.Stat(confPath); err != nil {
		return "", nil, false
	}

	props, err := readProperties(confPath)
	if err != nil {
		return "", nil, false
	}
	return homeDir, props, true
}

// --- Check Implementations ---

func CheckRedisWeakPassword() (bool, error) {
	procs, _ := findProcesses("redis-server")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		confPath := findConfigFile(proc, "", []string{"/etc/redis/redis.conf", "/etc/redis.conf"})
		if confPath == "" {
			continue
		}

		file, err := os.Open(confPath)
		if err != nil {
			continue
		}

		var requirepass, masterauth string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if m := reRequirepass.FindStringSubmatch(line); len(m) > 1 {
				requirepass = m[1]
			}
			if m := reMasterauth.FindStringSubmatch(line); len(m) > 1 {
				masterauth = m[1]
			}
		}
		file.Close()

		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)
		if requirepass == "" {
			risks = append(risks, fmt.Sprintf("High Risk: %s No requirepass set in Redis config", procLabel))
		} else {
			if requirepass == "redis" || requirepass == "admin" {
				risks = append(risks, fmt.Sprintf("High Risk: %s Redis using default password", procLabel))
			} else if isWeakPassword(requirepass) {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s Weak requirepass detected", procLabel))
			}
		}
		if masterauth != "" {
			if masterauth == "redis" || masterauth == "admin" {
				risks = append(risks, fmt.Sprintf("High Risk: %s Redis masterauth using default password", procLabel))
			} else if isWeakPassword(masterauth) {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s Weak masterauth detected", procLabel))
			}
		}
	}
	return collectRisks(risks)
}

func CheckMysqlWeakPassword() (bool, error) {
	procs, _ := findProcesses("mysqld")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		confPath := findConfigFile(proc, "--defaults-file", []string{
			"/etc/my.cnf", "/etc/mysql/my.cnf", "/var/lib/my.cnf", "/var/lib/mysql/my.cnf",
		})
		if confPath == "" {
			continue
		}

		file, err := os.Open(confPath)
		if err != nil {
			continue
		}

		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || line == "" {
				continue
			}
			if m := reMysqlPass.FindStringSubmatch(line); len(m) > 1 {
				pass := m[1]
				if pass == "root" || pass == "mysql" {
					risks = append(risks, fmt.Sprintf("High Risk: %s MySQL using default password", procLabel))
				} else if isWeakPassword(pass) {
					risks = append(risks, fmt.Sprintf("Medium Risk: %s Weak password detected in MySQL config", procLabel))
				}
			}
		}
		file.Close()
	}
	return collectRisks(risks)
}

func CheckPostgresWeakPassword() (bool, error) {
	procs, _ := findProcesses("postgres")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		var dataDir string
		re := regexp.MustCompile(`-D\s+(\S+)`)
		match := re.FindStringSubmatch(proc.Cmdline)
		if len(match) > 1 {
			dataDir = match[1]
		}

		var hbaPaths []string
		if dataDir != "" {
			hbaPaths = append(hbaPaths, filepath.Join(dataDir, "pg_hba.conf"))
		}
		candidates := []string{
			"/var/lib/pgsql/data/pg_hba.conf",
			"/var/lib/postgresql/data/pg_hba.conf",
		}
		pgVersionDirs, _ := filepath.Glob("/etc/postgresql/*/main/pg_hba.conf")
		candidates = append(candidates, pgVersionDirs...)
		pgVersionDirs2, _ := filepath.Glob("/var/lib/postgresql/*/main/pg_hba.conf")
		candidates = append(candidates, pgVersionDirs2...)
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				hbaPaths = append(hbaPaths, c)
			}
		}

		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)
		for _, hbaPath := range hbaPaths {
			content, err := os.ReadFile(hbaPath)
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(strings.NewReader(string(content)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					method := fields[len(fields)-1]
					if method == "trust" {
						risks = append(risks, fmt.Sprintf("High Risk: %s PostgreSQL allows 'trust' authentication in %s", procLabel, hbaPath))
					}
				}
			}
			break
		}
	}
	return collectRisks(risks)
}

func CheckNacosWeakPassword() (bool, error) {
	procs, _ := findProcesses("nacos")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		homeDir, props, ok := findNacosHomeAndProps(proc)
		if !ok {
			continue
		}
		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)

		if val, ok := props["nacos.core.auth.enabled"]; ok && val == "false" {
			risks = append(risks, fmt.Sprintf("High Risk: %s Nacos authentication is disabled", procLabel))
		}

		defaultSecret := "SecretKey012345678901234567890123456789012345678901234567890123456789"
		if val, ok := props["nacos.core.auth.plugin.nacos.token.secret.key"]; ok {
			if val == defaultSecret {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default token secret key", procLabel))
			} else if len(val) < 32 {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s Nacos token secret key is too short", procLabel))
			}
		}

		if val, ok := props["nacos.core.auth.default.token.secret.key"]; ok {
			if val == defaultSecret {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default token secret key (legacy config)", procLabel))
			}
		}

		schemaPath := filepath.Join(homeDir, "conf", "mysql-schema.sql")
		if content, err := os.ReadFile(schemaPath); err == nil {
			if strings.Contains(string(content), "nacos/nacos") {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos mysql-schema.sql contains default password", procLabel))
			}
		}
		derbyPath := filepath.Join(homeDir, "conf", "derby-schema.sql")
		if content, err := os.ReadFile(derbyPath); err == nil {
			if strings.Contains(string(content), "nacos/nacos") {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos derby-schema.sql contains default password", procLabel))
			}
		}
	}
	return collectRisks(risks)
}

func CheckNacosConfig() (bool, error) {
	procs, _ := findProcesses("nacos")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		homeDir, props, ok := findNacosHomeAndProps(proc)
		if !ok {
			continue
		}
		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)

		if val, ok := props["nacos.core.auth.enabled"]; ok && val == "false" {
			risks = append(risks, fmt.Sprintf("High Risk: %s nacos.core.auth.enabled=false", procLabel))
		}

		if val, ok := props["nacos.core.auth.admin.enabled"]; ok && val == "false" {
			risks = append(risks, fmt.Sprintf("High Risk: %s nacos.core.auth.admin.enabled=false", procLabel))
		}
		if val, ok := props["nacos.core.auth.console.enabled"]; ok && val == "false" {
			risks = append(risks, fmt.Sprintf("High Risk: %s nacos.core.auth.console.enabled=false", procLabel))
		}

		if val, ok := props["nacos.core.auth.enable.userAgentAuthWhite"]; ok && val != "false" {
			risks = append(risks, fmt.Sprintf("Medium Risk: %s nacos.core.auth.enable.userAgentAuthWhite should be false", procLabel))
		}

		defaultSecret := "SecretKey012345678901234567890123456789012345678901234567890123456789"
		if val, ok := props["nacos.core.auth.plugin.nacos.token.secret.key"]; ok {
			if val == defaultSecret {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default token secret key", procLabel))
			} else if len(val) < 32 {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s Nacos token secret key is too short", procLabel))
			}
		}

		if val, ok := props["nacos.core.auth.default.token.secret.key"]; ok {
			if val == defaultSecret {
				risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default legacy token secret key (1.2.0~2.0.4)", procLabel))
			}
		}

		if val, ok := props["nacos.core.auth.server.identity.key"]; ok && val == "serverIdentity" {
			risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default server identity key", procLabel))
		}
		if val, ok := props["nacos.core.auth.server.identity.value"]; ok && val == "security" {
			risks = append(risks, fmt.Sprintf("High Risk: %s Nacos using default server identity value", procLabel))
		}

		if val, ok := props["management.endpoints.web.exposure.include"]; ok && val == "*" {
			risks = append(risks, fmt.Sprintf("High Risk: %s All actuator endpoints exposed (include=*)", procLabel))
		}
		if val, ok := props["management.endpoints.web.exposure.exclude"]; !ok || val != "*" {
			risks = append(risks, fmt.Sprintf("Medium Risk: %s management.endpoints.web.exposure.exclude is not set to * (endpoints may be exposed)", procLabel))
		}

		schemaPath := filepath.Join(homeDir, "conf", "mysql-schema.sql")
		if content, err := os.ReadFile(schemaPath); err == nil {
			if strings.Contains(string(content), "nacos/nacos") {
				risks = append(risks, fmt.Sprintf("High Risk: %s mysql-schema.sql contains default password nacos/nacos", procLabel))
			}
		}
		derbyPath := filepath.Join(homeDir, "conf", "derby-schema.sql")
		if content, err := os.ReadFile(derbyPath); err == nil {
			if strings.Contains(string(content), "nacos/nacos") {
				risks = append(risks, fmt.Sprintf("High Risk: %s derby-schema.sql contains default password nacos/nacos", procLabel))
			}
		}
	}
	return collectRisks(risks)
}

func CheckArcheryConfig() (bool, error) {
	procs, _ := findProcesses("archery")
	if len(procs) == 0 {
		return true, nil
	}

	debugRe := regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*.*True`)

	var risks []string
	for _, proc := range procs {
		settingsPath := filepath.Join(proc.Cwd, "archery", "settings.py")
		content, err := os.ReadFile(settingsPath)
		if err != nil {
			continue
		}

		text := string(content)
		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)

		if debugRe.MatchString(text) {
			risks = append(risks, fmt.Sprintf("High Risk: %s Archery running in DEBUG mode", procLabel))
		}

		if strings.Contains(text, `hfusaf2m4ot#7)fkw#di2bu6(cv0@opwmafx5n#6=3d%x^hpl6`) {
			risks = append(risks, fmt.Sprintf("High Risk: %s Archery using default SECRET_KEY", procLabel))
		}
	}
	return collectRisks(risks)
}

func CheckXxlJobConfig() (bool, error) {
	procs, _ := findProcesses("xxl-job-admin")
	if len(procs) == 0 {
		return true, nil
	}

	var risks []string
	for _, proc := range procs {
		confPath := findConfigFile(proc, "-Dspring.config.location", []string{
			"/xxl-job/xxl-job-admin/src/main/resources/application.properties",
			"application.properties",
		})
		if confPath == "" {
			confPath = filepath.Join(proc.Cwd, "application.properties")
		}

		props, err := readProperties(confPath)
		if err != nil {
			continue
		}

		procLabel := fmt.Sprintf("[pid=%s]", proc.Pid)

		if token, ok := props["xxl.job.accessToken"]; ok {
			if token == "" {
				risks = append(risks, fmt.Sprintf("High Risk: %s XXL-JOB access token is empty", procLabel))
			} else if token == "default_token" {
				risks = append(risks, fmt.Sprintf("High Risk: %s XXL-JOB using default access token", procLabel))
			} else if isWeakPassword(token) {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s XXL-JOB access token is weak", procLabel))
			}
		} else {
			risks = append(risks, fmt.Sprintf("High Risk: %s XXL-JOB access token not configured", procLabel))
		}

		if pass, ok := props["spring.datasource.password"]; ok {
			if pass == "" {
				risks = append(risks, fmt.Sprintf("High Risk: %s XXL-JOB datasource password is empty", procLabel))
			} else if isWeakPassword(pass) {
				risks = append(risks, fmt.Sprintf("Medium Risk: %s XXL-JOB datasource password is weak", procLabel))
			}
		}
	}
	return collectRisks(risks)
}
