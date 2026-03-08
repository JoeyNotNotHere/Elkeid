package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/container"
	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/process"
	plugins "github.com/bytedance/plugins"
	"go.uber.org/zap"
)

type App struct {
	Name    string
	Version string
	Type    string
	Conf    string
	Matched bool
}
type AppRule struct {
	name              string
	versionRegex      *regexp.Regexp
	versionArgs       []string
	_type             string
	versionTrimPrefix string
	versionTrimSuffix string
	confFunc          func(RuleContext) string
	matchFunc         func(RuleContext) ([]byte, *App)
	sub               *AppRule
}
type RuleContext struct {
	enterContainer bool
	comm           string
	uid            uint32
	gid            uint32
	dir            string
	containerID    string
	exe            string
	cmdline        string
	ppid           string
	proc           process.Process
	appVersion     string
}

var (
	apacheRule = &AppRule{
		name:              "apache",
		_type:             "web_service",
		versionRegex:      regexp.MustCompile(`Apache\/(\d+\.)+\d+`),
		versionArgs:       []string{"-v"},
		versionTrimPrefix: "Apache/",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`-f\s\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimPrefix(string(res), "-f ")
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			for _, path := range []string{
				"/usr/local/apache2/conf/httpd.conf", "/etc/apache2/apache2.conf",
				"/etc/httpd/conf/httpd.conf", "/etc/apache2/httpd.conf"} {
				if _, err := os.Stat(filepath.Join(rootPath, path)); err == nil {
					return path
				}
			}
			return ""
		},
	}
	nginxRule = &AppRule{
		name:              "nginx",
		_type:             "web_service",
		versionRegex:      regexp.MustCompile(`nginx\/(\d+\.)+\d+`),
		versionTrimPrefix: "nginx/",
		versionArgs:       []string{"-v"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`-c\s\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimPrefix(string(res), "-c ")
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/etc/nginx/nginx.conf")); err == nil {
				return "/etc/nginx/nginx.conf"
			}
			return ""
		},
		matchFunc: func(rc RuleContext) ([]byte, *App) {
			cmdline := rc.cmdline
			if strings.Contains(cmdline, "apisix") {
				return nil, &App{Name: "apache-apisix", Type: "web_service", Matched: true}
			}
			return nil, nil
		},
		sub: &AppRule{
			name:              "tengine",
			_type:             "web_service",
			versionRegex:      regexp.MustCompile(`Tengine\/(\d+\.)+\d+`),
			versionTrimPrefix: `Tengine/`,
			versionArgs:       []string{"-v"},
			confFunc: func(rc RuleContext) string {
				res := regexp.MustCompile(`-c\s\S+`).Find([]byte(rc.cmdline))
				if res != nil {
					return strings.TrimPrefix(string(res), "-c ")
				}
				rootPath := "/"
				if rc.enterContainer {
					rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
				}
				if _, err := os.Stat(filepath.Join(rootPath, "/etc/nginx/nginx.conf")); err == nil {
					return "/etc/nginx/nginx.conf"
				}
				return ""
			},
			matchFunc: func(rc RuleContext) ([]byte, *App) {
				cmdline := rc.cmdline
				if strings.Contains(cmdline, "apisix") {
					return nil, &App{Name: "apache-apisix", Type: "web_service", Matched: true}
				}
				return nil, nil
			},
			sub: &AppRule{
				name:              "openresty",
				_type:             "web_service",
				versionRegex:      regexp.MustCompile(`openresty\/(\d+\.)+\d+`),
				versionTrimPrefix: `openresty/`,
				versionArgs:       []string{"-v"},
				confFunc: func(rc RuleContext) string {
					res := regexp.MustCompile(`-c\s\S+`).Find([]byte(rc.cmdline))
					if res != nil {
						return strings.TrimPrefix(string(res), "-c ")
					}
					rootPath := "/"
					if rc.enterContainer {
						rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
					}
					if _, err := os.Stat(filepath.Join(rootPath, "/etc/nginx/nginx.conf")); err == nil {
						return "/etc/nginx/nginx.conf"
					}
					return ""
				},
				matchFunc: func(rc RuleContext) ([]byte, *App) {
					cmdline := rc.cmdline
					if strings.Contains(cmdline, "apisix") {
						return nil, &App{Name: "apache-apisix", Type: "web_service", Matched: true}
					}
					return nil, nil
				},
			},
		},
	}
	redisRule = &AppRule{
		name:              "redis",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`v=(\d+\.)+\d+`),
		versionArgs:       []string{"-v"},
		versionTrimPrefix: "v=",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`\S+\.conf`).Find([]byte(rc.cmdline))
			if res != nil {
				return string(res)
			}
			return ""
		},
	}
	grafanaRule = &AppRule{
		name:              "grafana",
		_type:             "devops",
		versionRegex:      regexp.MustCompile(`Version\s(\d+\.)+\d+\S+`),
		versionArgs:       []string{"-v"},
		versionTrimPrefix: "Version ",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`-config(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "-config"), "="))
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/usr/local/etc/grafana/grafana.ini")); err == nil {
				return "/usr/local/etc/grafana/grafana.ini"
			}
			if cwd, err := rc.proc.Cwd(); err == nil {
				confPath := filepath.Join(cwd, "/conf/defaults.ini")
				if _, err := os.Stat(filepath.Join(rootPath, confPath)); err == nil {
					return confPath
				}
			}
			return ""
		},
	}
	rabbitmqRule = &AppRule{
		name:  "rabbitmq",
		_type: "message_queue",
	}
	mysqlRule = &AppRule{
		name:              "mysql",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`Ver\s(\d+\.)+\d+\S+`),
		versionArgs:       []string{"-V"},
		versionTrimPrefix: "Ver ",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--defaults-file=\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimPrefix(string(res), "--defaults-file=")
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			for _, path := range []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/usr/etc/my.cnf"} {
				if _, err := os.Stat(filepath.Join(rootPath, path)); err == nil {
					return path
				}
			}
			return ""
		},
	}
	postgresqlRule = &AppRule{
		name:         "postgresql",
		_type:        "database",
		versionRegex: regexp.MustCompile(`(\d+\.)+\d+`),
		versionArgs:  []string{"-V"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`config_file=\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimPrefix(string(res), "config_file=")
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			pgdata := regexp.MustCompile(`-D\s\S+`).Find([]byte(rc.cmdline))
			if pgdata != nil {
				path := filepath.Join(strings.TrimPrefix(string(pgdata), "-D "), "postgresql.conf")
				if _, err := os.Stat(filepath.Join(rootPath, path)); err == nil {
					return path
				}
			}
			if envs, err := rc.proc.Envs(); err == nil {
				if pgdata, ok := envs["PGDATA"]; ok {
					path := filepath.Join(pgdata, "postgresql.conf")
					if _, err := os.Stat(filepath.Join(rootPath, path)); err == nil {
						return path
					}
				}
			}
			return ""
		},
	}
	mongodbRule = &AppRule{
		name:              "mongodb",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`db\sversion\sv(\d+\.)+\d+`),
		versionTrimPrefix: "db version v",
		versionArgs:       []string{"--version"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config"), "="))
			}
			res = regexp.MustCompile(`-f\s+\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(string(res), "-f"))
			}
			return ""
		},
	}
	etcdRule = &AppRule{
		name:              "etcd",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`etcd\sVersion:\s(\d+\.)+\d+`),
		versionTrimPrefix: "etcd Version: ",
		versionArgs:       []string{"--version"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config-file(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config-file"), "="))
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if envs, err := rc.proc.Envs(); err == nil {
				if path, ok := envs["ETCD_CONFIG_FILE"]; ok {
					if _, err := os.Stat(filepath.Join(rootPath, path)); err == nil {
						return path
					}
				}
			}
			return ""
		},
	}
	prometheusRule = &AppRule{
		name:              "prometheus",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`prometheus,\sversion\s(\d+\.)+\d+`),
		versionTrimPrefix: "prometheus, version ",
		versionArgs:       []string{"--version"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config\.file(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config.file"), "="))
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/etc/prometheus/prometheus.yml")); err == nil {
				return "/etc/prometheus/prometheus.yml"
			}
			return ""
		},
	}
	sqlserverRule = &AppRule{
		name:              "sqlserver",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`(\d+\.){3}\d+`),
		versionTrimPrefix: "",
		versionArgs:       []string{"-v"},
		confFunc: func(rc RuleContext) string {
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/var/opt/mssql/mssql-conf")); err == nil {
				return "/var/opt/mssql/mssql-conf"
			}
			return ""
		},
	}
	phpfpmRule = &AppRule{
		name:              "php-fpm",
		_type:             "web_service",
		versionRegex:      regexp.MustCompile(`PHP\s(\d+\.)+\d+`),
		versionTrimPrefix: "PHP ",
		versionArgs:       []string{"-v"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`\(.+\)`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSuffix(strings.TrimPrefix(string(res), "("), ")")
			}
			return ""
		},
	}
	dockerRule = &AppRule{
		name:              "docker",
		_type:             "container_component",
		versionRegex:      regexp.MustCompile(`Docker\sversion\s(\d+\.)+\d+`),
		versionTrimPrefix: "Docker version ",
		versionArgs:       []string{"-v"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config-file(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config-file"), "="))
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/etc/docker/daemon.json")); err == nil {
				return "/etc/docker/daemon.json"
			}
			return ""
		},
	}
	containerdRule = &AppRule{
		name:              "containerd",
		_type:             "container_component",
		versionRegex:      regexp.MustCompile(`(\d+\.)+\d+`),
		versionTrimPrefix: "",
		versionArgs:       []string{"-v"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config"), "="))
			}
			res = regexp.MustCompile(`-c\s\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimPrefix(string(res), "-c ")
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/etc/containerd/config.toml")); err == nil {
				return "/etc/containerd/config.toml"
			}
			return ""
		},
	}
	kubeletRule = &AppRule{
		name:              "kubelet",
		_type:             "container_component",
		versionRegex:      regexp.MustCompile(`v(\d+\.)+\d+\S+`),
		versionTrimPrefix: "v",
		versionArgs:       []string{"--version"},
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--config(=|\s+)\S+`).Find([]byte(rc.cmdline))
			if res != nil {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(string(res), "--config"), "="))
			}
			rootPath := "/"
			if rc.enterContainer {
				rootPath = filepath.Join("/proc", rc.proc.Pid(), "root")
			}
			if _, err := os.Stat(filepath.Join(rootPath, "/var/lib/kubelet/config")); err == nil {
				return "/var/lib/kubelet/config"
			}
			return ""
		},
	}
	ruleMap = map[string]*AppRule{
		"apache2":         apacheRule,
		"httpd":           apacheRule,
		"nginx":           nginxRule,
		"redis-server":    redisRule,
		"rabbitmq-server": rabbitmqRule,
		"grafana-server":  grafanaRule,
		"mysqld":          mysqlRule,
		"postgres":        postgresqlRule,
		"mongod":          mongodbRule,
		"etcd":            etcdRule,
		"prometheus":      prometheusRule,
		"sqlservr":        sqlserverRule,
		"php-fpm":         phpfpmRule,
		"dockerd":         dockerRule,
		"containerd":      containerdRule,
		"kubelet":         kubeletRule,
		"java":            javaRule,
		"python":          pythonRule,
		"python2":         pythonRule,
		"python3":         pythonRule,
		"uwsgi":           pythonRule,
		"gunicorn":        pythonRule,
		"node":            nodeRule,
		"tidb-server":     tidbRule,
		"zabbix_server":   zabbixRule,
		"rancher":         rancherRule,
		"doris_be":        dorisBeRule,
		"koko":            jumpserverKokoRule,
		"salt-master":     pythonRule,
		"salt-minion":     pythonRule,
		"ansible":         pythonRule,
		"ansible-playbook": pythonRule,
	}
)

var (
	// Define Java apps
	kafkaRule = &AppRule{
		name:              "kafka",
		_type:             "message_queue",
		versionRegex:      regexp.MustCompile(`kafka_\d+\.\d+-(\d+\.\d+\.\d+)`),
		versionTrimPrefix: "",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`config\/server\.properties`).Find([]byte(rc.cmdline))
			if res != nil {
				return string(res)
			}
			return ""
		},
	}
	rocketmqRule = &AppRule{
		name:  "rocketmq",
		_type: "message_queue",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	nacosRule = &AppRule{
		name:              "nacos",
		_type:             "service_discovery",
		versionRegex:      regexp.MustCompile(`nacos-server-(\d+\.\d+\.\d+)`),
		versionTrimPrefix: "",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`-Dnacos\.home=(\S+)`).FindSubmatch([]byte(rc.cmdline))
			if len(res) > 1 {
				return filepath.Join(string(res[1]), "conf/application.properties")
			}
			return ""
		},
	}
	elasticsearchRule = &AppRule{
		name:              "elasticsearch",
		_type:             "database",
		versionRegex:      regexp.MustCompile(`elasticsearch-(\d+\.\d+\.\d+)`),
		versionTrimPrefix: "",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`-Des\.path\.conf=(\S+)`).FindSubmatch([]byte(rc.cmdline))
			if len(res) > 1 {
				return filepath.Join(string(res[1]), "elasticsearch.yml")
			}
			return ""
		},
	}
	jenkinsRule = &AppRule{
		name:         "jenkins",
		_type:        "devops",
		versionRegex: nil,
		confFunc: func(rc RuleContext) string {
			if envs, err := rc.proc.Envs(); err == nil {
				if home, ok := envs["JENKINS_HOME"]; ok {
					return filepath.Join(home, "config.xml")
				}
			}
			return ""
		},
	}
	logstashRule = &AppRule{
		name:  "logstash",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	djangoRule = &AppRule{
		name:  "django",
		_type: "web_service",
		confFunc: func(rc RuleContext) string {
			res := regexp.MustCompile(`--settings=(\S+)`).FindSubmatch([]byte(rc.cmdline))
			if len(res) > 1 {
				return string(res[1])
			}
			if envs, err := rc.proc.Envs(); err == nil {
				if s, ok := envs["DJANGO_SETTINGS_MODULE"]; ok {
					return s
				}
			}
			return ""
		},
	}
	// General Java Rule
	javaRule = &AppRule{
		name: "java_app",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	// General Python Rule
	pythonRule = &AppRule{
		name: "python_app",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	// General Node.js Rule
	nodeRule = &AppRule{
		name: "node_app",
		confFunc: func(rc RuleContext) string {
			return ""
		},
		matchFunc: func(rc RuleContext) ([]byte, *App) {
			cmdline := rc.cmdline
			if strings.Contains(cmdline, "kibana") {
				return nil, &App{Name: "kibana", Type: "web_service", Matched: true}
			}
			return nil, nil
		},
	}
	// Independent binary rules
	ansibleRule = &AppRule{
		name:  "ansible",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	saltstackRule = &AppRule{
		name:  "saltstack",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	jumpserverRule = &AppRule{
		name:  "jumpserver",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	tidbRule = &AppRule{
		name:  "tidb",
		_type: "database",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	zabbixRule = &AppRule{
		name:  "zabbix",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	rancherRule = &AppRule{
		name:  "rancher",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	// Independent binary rules for components not running on JVM/Python
	dorisBeRule = &AppRule{
		name:  "doris",
		_type: "database",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
	jumpserverKokoRule = &AppRule{
		name:  "jumpserver",
		_type: "devops",
		confFunc: func(rc RuleContext) string {
			return ""
		},
	}
)

// extractVersionFromCmdline uses FindSubmatch to extract version from cmdline via capture group.
// Falls back to FindString if no capture group found.
func extractVersionFromCmdline(cmdline string, re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	matches := re.FindStringSubmatch(cmdline)
	if len(matches) > 1 {
		return matches[1]
	}
	return re.FindString(cmdline)
}

type javaAppEntry struct {
	keyword string
	rule    *AppRule
	name    string
	appType string
}

var javaRuleApps = []javaAppEntry{
	{keyword: "kafka", rule: kafkaRule},
	{keyword: "rocketmq", rule: rocketmqRule},
	{keyword: "nacos", rule: nacosRule},
	{keyword: "elasticsearch", rule: elasticsearchRule},
	{keyword: "jenkins", rule: jenkinsRule},
	{keyword: "logstash", rule: logstashRule},
}

var javaSimpleApps = []javaAppEntry{
	{keyword: "hadoop", name: "hadoop", appType: "big_data"},
	{keyword: "druid", name: "druid", appType: "database"},
	{keyword: "canal", name: "canal", appType: "middleware"},
	{keyword: "doris", name: "doris", appType: "database"},
	{keyword: "nexus", name: "nexus", appType: "devops"},
	{keyword: "ruoyi", name: "ruoyi", appType: "web_service"},
	{keyword: "skywalking", name: "skywalking", appType: "devops"},
	{keyword: "xxl-job", name: "xxl-job", appType: "devops"},
	{keyword: "ambari", name: "ambari", appType: "devops"},
	{keyword: "logbase", name: "logbase", appType: "big_data"},
}

type pythonAppEntry struct {
	keyword  string
	keyword2 string
	rule     *AppRule
	name     string
	appType  string
}

var pythonSimpleApps = []pythonAppEntry{
	{keyword: "manage.py", keyword2: "django", rule: djangoRule},
	{keyword: "ansible", name: "ansible", appType: "devops"},
	{keyword: "salt", name: "saltstack", appType: "devops"},
	{keyword: "jumpserver", name: "jumpserver", appType: "devops"},
	{keyword: "archery", name: "archery", appType: "devops"},
}

func dispatchJavaApp(rc RuleContext) ([]byte, *App) {
	cmdline := rc.cmdline
	for _, entry := range javaRuleApps {
		if strings.Contains(cmdline, entry.keyword) {
			if entry.rule.versionRegex != nil && rc.appVersion == "" {
				rc.appVersion = extractVersionFromCmdline(cmdline, entry.rule.versionRegex)
			}
			return entry.rule.GenerateApp(rc)
		}
	}
	for _, entry := range javaSimpleApps {
		if strings.Contains(cmdline, entry.keyword) {
			return nil, &App{Name: entry.name, Type: entry.appType, Matched: true}
		}
	}
	return nil, nil
}

func dispatchPythonApp(rc RuleContext) ([]byte, *App) {
	cmdline := rc.cmdline
	for _, entry := range pythonSimpleApps {
		matched := strings.Contains(cmdline, entry.keyword)
		if !matched && entry.keyword2 != "" {
			matched = strings.Contains(cmdline, entry.keyword2)
		}
		if matched {
			if entry.rule != nil {
				return entry.rule.GenerateApp(rc)
			}
			return nil, &App{Name: entry.name, Type: entry.appType, Matched: true}
		}
	}
	return nil, nil
}

func (r *AppRule) GenerateApp(rc RuleContext) ([]byte, *App) {
	// Check matchFunc first (fixes APISIX/Kibana recognition)
	if r.matchFunc != nil {
		if output, app := r.matchFunc(rc); app != nil {
			if r.confFunc != nil {
				app.Conf = r.confFunc(rc)
			}
			return output, app
		}
	}

	if r.name == "java_app" {
		return dispatchJavaApp(rc)
	}
	if r.name == "python_app" {
		return dispatchPythonApp(rc)
	}

	var output []byte
	var app *App
	if r.sub != nil {
		output, app = r.sub.GenerateApp(rc)
		if app != nil && app.Matched {
			return nil, app
		}
	}
	p, err := process.NewProcess(rc.ppid)
	if err != nil {
		return nil, nil
	}
	ppidComm, err := p.Comm()
	if err != nil {
		return nil, nil
	}
	if ppidComm == rc.comm {
		return nil, nil
	}
	app = &App{}
	app.Name = r.name
	app.Type = r._type
	if rc.appVersion != "" {
		app.Version = rc.appVersion
	} else {
		if r.versionRegex != nil {
			if output == nil {
				var err error
				output, err = ExecAs(rc.enterContainer, rc.uid, rc.gid, rc.dir, rc.containerID, rc.exe, r.versionArgs...)
				if err != nil {
					zap.S().Warn("app exec failed: ", err.Error())
					return nil, app
				}
			}
			res := r.versionRegex.Find(output)
			if res != nil {
				app.Version = string(res)
				if r.versionTrimPrefix != "" {
					app.Version = strings.TrimPrefix(app.Version, r.versionTrimPrefix)
				}
				if r.versionTrimSuffix != "" {
					app.Version = strings.TrimSuffix(app.Version, r.versionTrimSuffix)
				}
				app.Matched = true
			}
		}
	}
	if r.confFunc != nil {
		app.Conf = r.confFunc(rc)
	}
	return output, app
}

func ExecAs(enterContainer bool, uid, gid uint32, dir string, containerID, name string, arg ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	if enterContainer && containerID != "" {
		var err error
		var res []byte
		clients := container.NewClients()
		for _, c := range clients {
			// ! Maybe privilege escalation？
			res, err = c.Exec(ctx, containerID, name, arg...)
			c.Close()
			if err == nil {
				return res, nil
			}
			if !container.IsNotFound(err) {
				return nil, err
			}
		}
		return nil, err
	} else if enterContainer && containerID == "" {
		return nil, fmt.Errorf("container id is required")
	} else {
		cmd := exec.CommandContext(ctx, name, arg...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uid,
				Gid: gid,
			},
		}
		cmd.Dir = dir
		return cmd.CombinedOutput()
	}
}

type AppHandler struct{}

func (h *AppHandler) Name() string {
	return "app"
}
func (h *AppHandler) DataType() int {
	return 5060
}

func (h *AppHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	procs, err := process.Processes(false)
	if err != nil {
		return
	}
	versionCache := map[string]string{}
	for _, proc := range procs {
		time.Sleep(process.TraversalInterval)
		comm, err := proc.Comm()
		if err != nil {
			continue
		}
		stat, err := proc.Stat()
		if err != nil {
			continue
		}
		status, err := proc.Status()
		if err != nil {
			continue
		}
		euid, err := strconv.ParseUint(status.Euid, 10, 64)
		if err != nil {
			continue
		}
		egid, err := strconv.ParseUint(status.Egid, 10, 64)
		if err != nil {
			continue
		}
		cmdline, err := proc.Cmdline()
		if err != nil {
			continue
		}
		exe, err := proc.Exe()
		if err != nil {
			continue
		}
		pns, err := proc.Namespace("pid")
		if err != nil {
			continue
		}
		dir, err := proc.Cwd()
		if err != nil {
			continue
		}
		var containerID, containerName string
		m, ok := cache.Get(5056, pns)
		if ok {
			containerID = m["container_id"]
			containerName = m["container_name"]
		}
		cacheKey := exe + "|" + pns
		version := versionCache[cacheKey]
		if rule, ok := ruleMap[comm]; ok {
			_, app := rule.GenerateApp(RuleContext{
				enterContainer: process.PnsDiffWithRpns(pns),
				uid:            uint32(euid),
				gid:            uint32(egid),
				ppid:           stat.Ppid,
				containerID:    containerID,
				exe:            exe,
				cmdline:        cmdline,
				proc:           proc,
				appVersion:     version,
				comm:           comm,
				dir:            dir,
			})
			if app != nil {
				versionCache[cacheKey] = app.Version
				c.SendRecord(&plugins.Record{
					DataType:  int32(h.DataType()),
					Timestamp: time.Now().Unix(),
					Data: &plugins.Payload{
						Fields: map[string]string{
							"name":           app.Name,
							"type":           app.Type,
							"sversion":       app.Version,
							"conf":           app.Conf,
							"container_id":   containerID,
							"container_name": containerName,
							"pid":            proc.Pid(),
							"exe":            exe,
							"start_time":     stat.StartTime,
							"package_seq":    seq,
						},
					},
				})
			}
		}
	}
}
