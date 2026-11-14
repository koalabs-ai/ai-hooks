// Package guard decides, before a shell command runs, whether it is likely to
// print secret values, and says how to repeat it safely.
//
// Two kinds of rules:
//
//   - redact rules (rules.json, user-extensible): "this command tends to print
//     secrets; it is fine if its output goes through the redactor".
//   - structural rules A-F (this file): a small shell-aware analysis (pipes,
//     quotes, heredocs, ssh '...' bodies) that finds a secret file or variable
//     reaching the terminal.
//
// The guard fails open: any internal problem allows the command.
package guard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

//go:embed rules.json
var defaultRules []byte

// Rule is one redact rule.
type Rule struct {
	ID     string   `json:"id"`
	Why    string   `json:"why"`
	Match  []string `json:"match"`
	Unless []string `json:"unless"` // the rule does not fire when any of these matches a line
	re     []*regexp.Regexp
	unless []*regexp.Regexp
}

// Config is the rules file format (embedded default, optional user file).
type Config struct {
	Version     int      `json:"version"`
	RedactRules []Rule   `json:"redact_rules"`
	SecretPaths []string `json:"secret_paths"` // extra regex alternatives for "a file that holds secrets"
	Disable     []string `json:"disable"`      // rule ids to switch off
	Allow       []string `json:"allow"`        // a command matching any of these regexes is allowed
	Redactors   []string `json:"redactors"`    // extra regexes that mean "this command is piped through a redactor"
}

// Result is the guard's verdict for one command.
type Result struct {
	Blocked    bool
	Rule       string // rule id (A..F rules use ids like "print-secret-file")
	Detail     string // what exactly was found
	Overridden string // "noredact" or "ok" when an override comment let a blocked command through
	Kind       string // "redact" or "structural"
}

// Message is the one-line instruction for the agent.
func (r Result) Message() string {
	if r.Kind == "redact" {
		return msg("redact", r.Detail)
	}
	return msg("structural", r.Detail)
}

var catalogs = map[string]map[string]string{
	"en": {
		"redact":     "{detail}. Re-run through the redactor: `<command> 2>&1 | ai-hooks redact` (or append `# noredact` to see raw output; the override is logged).",
		"structural": "{detail}. Print names only (`cut -d= -f1`), a fingerprint (`sha256sum`) or pipe through `ai-hooks redact`; append `# ai-hooks: ok` if no secret value is printed (the override is logged).",
	},
}

func msg(key, detail string) string {
	lang := strings.ToLower(os.Getenv("AI_HOOKS_LANG"))
	if i := strings.IndexAny(lang, "_.-"); i > 0 {
		lang = lang[:i]
	}
	c, ok := catalogs[lang]
	if !ok {
		c = catalogs["en"]
	}
	return strings.Replace(c[key], "{detail}", detail, 1)
}

// RegisterCatalog adds or replaces a message catalog (keys: redact, structural).
func RegisterCatalog(lang string, c map[string]string) { catalogs[lang] = c }

// ---------------------------------------------------------------- engine

type engine struct {
	cfg        Config
	rules      []Rule
	disabled   map[string]bool
	allow      []*regexp.Regexp
	redactors  []*regexp.Regexp
	secretFile *regexp.Regexp
	mu         sync.Mutex // decide() keeps per-call state in the engine: one at a time
	budget     int        // bytes of analysis left for this command; pathological input fails open
	execMode   bool       // the command runs under ai-hooks exec: all of its output is redacted
}

var (
	engOnce sync.Once
	eng     *engine
	engErr  error
)

// RulesPath is where the optional user rules file lives.
func RulesPath() string {
	if p := os.Getenv("AI_HOOKS_RULES"); p != "" {
		return p
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ai-hooks", "rules.json")
	}
	return ""
}

// DefaultRulesJSON returns the embedded default rules file.
func DefaultRulesJSON() []byte { return defaultRules }

func getEngine() (*engine, error) {
	engOnce.Do(func() { eng, engErr = newEngine(RulesPath()) })
	return eng, engErr
}

func newEngine(userPath string) (*engine, error) {
	var cfg Config
	if err := json.Unmarshal(defaultRules, &cfg); err != nil {
		return nil, err
	}
	var warn error
	if userPath != "" {
		if b, err := os.ReadFile(userPath); err == nil {
			var u Config
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			err := dec.Decode(&u)
			if err != nil {
				warn = err
				u = Config{}
				if json.Unmarshal(b, &u) != nil { // not even JSON: keep the defaults
					u = Config{}
				}
			}
			{
				cfg.RedactRules = append(cfg.RedactRules, u.RedactRules...)
				cfg.SecretPaths = append(cfg.SecretPaths, u.SecretPaths...)
				cfg.Disable = append(cfg.Disable, u.Disable...)
				cfg.Allow = append(cfg.Allow, u.Allow...)
				cfg.Redactors = append(cfg.Redactors, u.Redactors...)
			}
		}
	}
	e := &engine{cfg: cfg, disabled: map[string]bool{}}
	for _, d := range cfg.Disable {
		e.disabled[d] = true
	}
	for _, r := range cfg.RedactRules {
		if e.disabled[r.ID] {
			continue
		}
		ok := true
		for _, m := range r.Match {
			re, err := regexp.Compile(m)
			if err != nil {
				warn, ok = err, false
				break
			}
			r.re = append(r.re, re)
		}
		for _, m := range r.Unless {
			if re, err := regexp.Compile(m); err == nil {
				r.unless = append(r.unless, re)
			} else {
				warn = err
			}
		}
		if ok && len(r.re) > 0 {
			e.rules = append(e.rules, r)
		}
	}
	for _, a := range cfg.Allow {
		if re, err := regexp.Compile(a); err == nil {
			e.allow = append(e.allow, re)
		} else {
			warn = err
		}
	}
	for _, a := range cfg.Redactors {
		if re, err := regexp.Compile(a); err == nil {
			e.redactors = append(e.redactors, re)
		} else {
			warn = err
		}
	}
	alts := `[\w.*?-]*\.env(?:\.[\w-]+)*|/proc/[\w$]+/environ`
	for _, p := range cfg.SecretPaths {
		if _, err := regexp.Compile(p); err == nil {
			alts += "|" + p
		} else {
			warn = err
		}
	}
	e.secretFile = regexp.MustCompile(`(^|[\s'"=:/<>(){}|;&,])(` + alts + `)($|[\s'"|;&)<>*?\[{},])`)
	return e, warn
}

// Check decides one command with the embedded rules plus the user file.
func Check(cmd string) Result {
	e, _ := getEngine()
	if e == nil {
		return Result{}
	}
	return e.decide(cmd, false)
}

// CheckExec decides a command that will run under `ai-hooks exec` (or the MCP
// safe_run tool): every byte of its output is redacted, so the rules that say
// "pipe it through the redactor" are satisfied. Two things stay blocked, because
// redaction goes by shape and a weak secret has none: printing a secret-named
// variable (echo $DB_PASSWORD, printenv DB_PASSWORD).
func CheckExec(cmd string) Result {
	e, _ := getEngine()
	if e == nil {
		return Result{}
	}
	return e.decide(cmd, true)
}

// CheckWith decides with an explicit rules file (tests, `guard --rules`).
func CheckWith(cmd, rulesPath string) (Result, error) {
	e, err := newEngine(rulesPath)
	if e == nil {
		return Result{}, err
	}
	return e.decide(cmd, false), err
}

var (
	reNoRedact   = regexp.MustCompile(`#\s*noredact\s*$`)
	reOverrideOK = regexp.MustCompile(`#\s*ai-hooks:\s*ok\s*$`)
	reRedactPipe = regexp.MustCompile(`(?m)(\|\s*&?\s*(\S*/)?ai-hooks\s+redact\b)|(^\s*(sudo\s+)?(\S*/)?ai-hooks\s+exec\b)`)
)

func (e *engine) decide(cmd string, execMode bool) (res Result) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if recover() != nil { // fail open
			res = Result{}
		}
	}()
	for _, a := range e.allow {
		if a.MatchString(cmd) {
			return Result{}
		}
	}
	over := ""
	if os.Getenv("AI_HOOKS_NO_OVERRIDE") == "1" {
		// strict mode: no comment can switch the guard off
	} else if reOverrideOK.MatchString(cmd) {
		over = "ok"
	} else if reNoRedact.MatchString(cmd) {
		over = "noredact"
	}
	e.budget = 8 << 20
	e.execMode = execMode
	if len(cmd) > 4<<20 { // too big to analyse: fail open, like any internal limit
		return Result{}
	}
	r := e.raw(cmd)
	if r.Blocked && over != "" {
		r.Blocked = false
		r.Overridden = over
	}
	return r
}

func (e *engine) raw(cmd string) Result {
	cmd = stripComments(cmd) // text in a comment must not make a command look safe
	// redact rules
	if !e.execMode && !anyLine(reRedactPipe, cmd) && !e.anyRedactor(cmd, true) {
		lc := strings.ToLower(cmd)
		for _, r := range e.rules {
			all := true
			for _, re := range r.re {
				if !anyLine(re, lc) {
					all = false
					break
				}
			}
			for _, re := range r.unless {
				if anyLine(re, lc) {
					all = false
				}
			}
			if all {
				return Result{Blocked: true, Rule: r.ID, Detail: r.Why, Kind: "redact"}
			}
		}
	}
	if id, why := e.check(cmd, 0); id != "" {
		return Result{Blocked: true, Rule: id, Detail: why, Kind: "structural"}
	}
	return Result{}
}

func anyLine(re *regexp.Regexp, s string) bool {
	for _, l := range strings.Split(s, "\n") {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- structural rules

var (
	secretName = regexp.MustCompile(`(?i)(PASS|PASSWD|PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|_KEY\b|KEY_|PRIVATE|` +
		`CREDENTIAL|DSN|(?:DATABASE|DB|PG|POSTGRES|REDIS|MONGO|AMQP|BROKER)_?(?:URL|URI))`)
	notSecretName = regexp.MustCompile(`(?i)^(?:OLD)?PWD$|_(?:PATH|FILE|DIR|NAME|ID)$`)
	notSecretFile = regexp.MustCompile(`(?i)(example|sample|template|dist)$`)
	dumpers       = regexp.MustCompile(`(^|[^\w.-])(?:[\w./~$-]*/)?(cat|tac|less|more|head|tail|grep|egrep|fgrep|rg|ugrep|sed|awk|gawk|mawk|` +
		`bat|batcat|strings|xxd|od|hexdump|nl|sort|uniq|column|tr|jq|yq|diff|cmp|comm|join|paste|cut|base64|rev|fold|fmt|pr|zcat|bzcat|xzcat|` +
		`perl|dd|openssl|gzip|bzip2|xz)([^\w./-]|$)|\bgit\s+(?:show|cat-file)\b`)
	bareRedirect = regexp.MustCompile(`^\s*<\s*\S+\s*$`)
	display      = map[string]bool{"cat": true, "tac": true, "less": true, "more": true, "head": true, "tail": true,
		"grep": true, "egrep": true, "rg": true, "ugrep": true, "sed": true, "awk": true, "gawk": true,
		"cut": true, "tr": true, "tee": true, "xxd": true, "od": true, "column": true, "nl": true, "sort": true, "uniq": true}
	safeSinks = []*regexp.Regexp{
		regexp.MustCompile(`(?m)(\|\s*&?\s*(\S*/)?ai-hooks\s+redact\b)|(^\s*(sudo\s+)?(\S*/)?ai-hooks\s+exec\b)`),
		regexp.MustCompile(`\bcut\s+(?:-d\s*['"]?=['"]?\s*)?-f\s*1([^\d,-]|$)`),
		regexp.MustCompile(`\bcut\s+-f\s*1\s+-d\s*['"]?=['"]?`),
		regexp.MustCompile(`\bsed\s+(?:-[Er]\s+)?['"]?s[/#|,:@!%~]=\.\*[/#|,:@!%~][^'"\s;]*[/#|,:@!%~]g?['"]?(\s|$)`),
		regexp.MustCompile(`\bawk\s+-F\s*['"]?=['"]?\s+['"]\{\s*print\s+\$1\s*\}`),
		regexp.MustCompile(`\b(?:wc|sha256sum|sha1sum|md5sum|b2sum)\b`),
		regexp.MustCompile(`\bgrep\s+(?:-[a-zA-Z]*[clLq][a-zA-Z]*\b|--count|--files-with(?:out)?-matches|--quiet)`),
		regexp.MustCompile(`(^|[^2\d])>\s*/dev/null(\s|$)`),
	}
	leakTee       = regexp.MustCompile(`\btee\s+(?:-\w+\s+)*/dev/(?:stderr|stdout|tty|fd/[12])\b`)
	grepNamesOnly = regexp.MustCompile(`\bgrep\s+[^|]*-[a-zA-Z]*o[a-zA-Z]*\s+(?:-E\s+)?['"]([^'"]*)['"]`)
	namesOnlyBad  = regexp.MustCompile(`\.|\\[SK]|\[\^|=.`)
	sedInplace    = regexp.MustCompile(`\bsed\s+(?:-[a-zA-Z]*\s+)*-i`)
	xtrace        = regexp.MustCompile(`\bset\s+(?:-[a-zA-Z]*x|-o\s+xtrace)|\b(?:ba|z|da)?sh\s+-[a-zA-Z]*x`)
	echoVar       = regexp.MustCompile(`(^|[^\w-])(?:echo|printf)\b[^|;&]*?\$(\{)?(#)?([A-Za-z_][A-Za-z0-9_]*)([^}]*\})?`)
	curlVerbose   = regexp.MustCompile(`(^|[^\w-])(--verbose\b|-[a-zA-Z]*v[a-zA-Z]*)([^\w-]|$)`)
	curlFlagVal   = regexp.MustCompile(`(?:-H\s*|--header(?:=|\s+)|-u\s*|--user(?:=|\s+)|--oauth2-bearer(?:=|\s+))('[^']*'|"(?:\\.|[^"\\])*"|\S+)`)
	stderrNull    = regexp.MustCompile(`[2&]>\s*/dev/null(\s|$)`)
	heredocHead   = regexp.MustCompile(`<<-?\s*(['"]?)(\w+)(['"]?)[^\n]*\n`)
	heredocExec   = regexp.MustCompile(`(?:\bssh\b|\b(?:ba|z|da)?sh\b)[^\n<|;&]*$`)
	echoSubst     = regexp.MustCompile(`(^|[^\w-])(?:echo|printf)\b[^|;&\n]*?\$\(`)
	quoted        = regexp.MustCompile(`'[^']*'|"(?:\\.|[^"\\])*"`)
	remoteSQ      = regexp.MustCompile(`(?s)(?:\bssh\b[^'"|]*?|\b(?:ba|z|da)?sh\s+-[a-z]*c\s+)(')(.+)'`)
	remoteDQ      = regexp.MustCompile(`(?s)(?:\bssh\b[^'"|]*?|\b(?:ba|z|da)?sh\s+-[a-z]*c\s+)(")(.+)"`)
	excludeFlag   = regexp.MustCompile(`--exclude(?:-dir)?=\S+`)
	envAssign     = regexp.MustCompile(`^[A-Za-z_]\w*=`)
	dockerExecEnv = regexp.MustCompile(`\bdocker\s+(?:exec|compose\s+exec)\b[^|]*\s(?:env|printenv)\s*['"]?\s*$`)
	printenvName  = regexp.MustCompile(`\bprintenv\s+([A-Za-z_]\w*)`)
	dockerInspect = regexp.MustCompile(`\bdocker\s+(?:container\s+)?inspect\b`)
	fmtFlag       = regexp.MustCompile(`\s(?:-f|--format)[\s=]`)
	dumpFlag      = regexp.MustCompile(`\s-[a-z]*p\b`)
	setAlone      = regexp.MustCompile(`^\s*set\s*$`)
	envAlone      = regexp.MustCompile(`^\s*(?:sudo\s+)?(?:\S*/)?env\s*$`)
	sysShowHead   = regexp.MustCompile(`\bsystemctl\b[^|]*?\bshow\b`)
	sysProp       = regexp.MustCompile(`(?:-p\s*|--property=)(\S*)`)
	bgOp          = regexp.MustCompile(`(^|[^>&])&($|[^&])`)
	varRef        = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)`)
	dollarBrace   = regexp.MustCompile(`\\([$"` + "`" + `\\])`)
	singleQ       = regexp.MustCompile(`'[^']*'`)
)

const maxDepth = 4

func skipParens(cmd string, j int) int {
	depth := 1
	for j < len(cmd) && depth > 0 {
		switch cmd[j] {
		case '(':
			depth++
		case ')':
			depth--
		}
		j++
	}
	return j
}

// stripHeredocs removes heredoc bodies (stdin of a program, not output) but
// returns the bodies whose program is a shell, so they can be analysed as commands.
func stripHeredocs(cmd string) (string, []string) {
	var out strings.Builder
	var bodies []string
	pos := 0
	for pos < len(cmd) {
		loc := heredocHead.FindStringSubmatchIndex(cmd[pos:])
		if loc == nil {
			break
		}
		start, hend := pos+loc[0], pos+loc[1]
		q1, tag, q3 := cmd[pos+loc[2]:pos+loc[3]], cmd[pos+loc[4]:pos+loc[5]], cmd[pos+loc[6]:pos+loc[7]]
		if q1 != q3 {
			out.WriteString(cmd[pos:hend])
			pos = hend
			continue
		}
		// body: lines up to one that is only the tag
		bodyEnd, termEnd := len(cmd), len(cmd)
		for ls := hend; ls <= len(cmd); {
			le := strings.IndexByte(cmd[ls:], '\n')
			var line string
			if le < 0 {
				line, le = cmd[ls:], len(cmd)
			} else {
				line, le = cmd[ls:ls+le], ls+le
			}
			if strings.TrimSpace(line) == tag {
				bodyEnd, termEnd = ls, le
				break
			}
			if le >= len(cmd) {
				break
			}
			ls = le + 1
		}
		lineStart := strings.LastIndexByte(cmd[:start], '\n') + 1
		if heredocExec.MatchString(cmd[lineStart:start]) {
			bodies = append(bodies, cmd[hend:bodyEnd])
		}
		out.WriteString(cmd[pos:hend]) // keeps "<<EOF ...\n"
		pos = termEnd
	}
	out.WriteString(cmd[pos:])
	return out.String(), bodies
}

// splitTop splits into pipelines (; && || newline) and each into stages (|),
// respecting quotes. $(...) and backticks are blanked: what they capture is
// not printed.
func splitTop(cmd string) [][]string {
	var pipelines [][]string
	var stages []string
	var cur []byte
	var q byte
	i, n := 0, len(cmd)
	flush := func() {
		stages = append(stages, string(cur))
		cur = nil
	}
	for i < n {
		c := cmd[i]
		if q != 0 {
			switch {
			case c == q:
				q = 0
			case c == '\\' && q == '"' && i+1 < n:
				cur = append(cur, c, cmd[i+1])
				i += 2
				continue
			case q == '"' && strings.HasPrefix(cmd[i:], "$("):
				i = skipParens(cmd, i+2)
				cur = append(cur, "$()"...)
				continue
			}
			cur = append(cur, c)
			i++
			continue
		}
		if c == '\'' || c == '"' {
			q = c
			cur = append(cur, c)
			i++
			continue
		}
		if c == '\\' && i+1 < n {
			cur = append(cur, c, cmd[i+1])
			i += 2
			continue
		}
		if strings.HasPrefix(cmd[i:], "$(") || strings.HasPrefix(cmd[i:], "<(") {
			i = skipParens(cmd, i+2)
			cur = append(cur, "$()"...)
			continue
		}
		if c == '`' {
			j := strings.IndexByte(cmd[i+1:], '`')
			cur = append(cur, "``"...)
			if j < 0 {
				i = n
			} else {
				i += j + 2
			}
			continue
		}
		if c == '|' && strings.HasPrefix(cmd[i:], "||") || c == '&' && strings.HasPrefix(cmd[i:], "&&") || c == ';' || c == '\n' {
			flush()
			pipelines = append(pipelines, stages)
			stages = nil
			if c == '|' || c == '&' {
				i += 2
			} else {
				i++
			}
			continue
		}
		if c == '|' {
			flush()
			i++
			continue
		}
		cur = append(cur, c)
		i++
	}
	flush()
	pipelines = append(pipelines, stages)
	var out [][]string
	for _, p := range pipelines {
		if strings.TrimSpace(strings.Join(p, "")) != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdWord(stage string) string {
	toks := strings.Fields(stage)
	for len(toks) > 0 && (envAssign.MatchString(toks[0]) || toks[0] == "sudo" || toks[0] == "exec" || toks[0] == "command" || toks[0] == "time") {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return ""
	}
	t := toks[0]
	return t[strings.LastIndexByte(t, '/')+1:]
}

func (e *engine) secretFiles(text string) []string {
	var out []string
	for pos := 0; pos <= len(text); {
		loc := e.secretFile.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			break
		}
		f := text[pos+loc[4] : pos+loc[5]]
		if !notSecretFile.MatchString(f) && !strings.HasPrefix(f, "process.env") && !strings.HasPrefix(f, "import.meta") {
			out = append(out, f)
		}
		next := pos + loc[5] // leave the trailing delimiter for the next match
		if next <= pos {
			next = pos + 1
		}
		pos = next
	}
	return out
}

func namesOnlyGrep(stage string) bool {
	m := grepNamesOnly.FindStringSubmatch(stage)
	if m == nil {
		return false
	}
	return !namesOnlyBad.MatchString(m[1])
}

func isSecretName(n string) bool { return secretName.MatchString(n) && !notSecretName.MatchString(n) }

// check returns (rule id, detail) of the first structural rule that trips.
func (e *engine) check(cmd string, depth int) (string, string) {
	e.budget -= len(cmd) + 64
	if depth > maxDepth || e.budget <= 0 {
		return "", ""
	}
	on := func(id string) bool { return !e.disabled[id] }
	cmd, bodies := stripHeredocs(cmd)
	for _, b := range bodies {
		if id, why := e.check(b, depth+1); id != "" {
			return id, why
		}
	}
	for _, m := range echoSubst.FindAllStringIndex(cmd, -1) {
		inner := cmd[m[1] : skipParens(cmd, m[1])-1]
		if id, why := e.check(inner, depth+1); id != "" {
			return id, why
		}
	}
	for _, pipe := range splitTop(cmd) {
		whole := strings.Join(pipe, " | ")
		if id, why := e.xargsRead(pipe, whole); id != "" {
			return id, why
		}
		safe := (e.execMode || e.anySafe(whole) || namesOnlyGrep(whole)) && !leakTee.MatchString(whole)
		for k, st := range pipe {
			// ssh '...' / sh -c '...': analyse what runs on the other side.
			if rm := findRemote(st); rm != nil {
				inner := st[rm[4]:rm[5]]
				if st[rm[2]:rm[3]] == `"` {
					inner = dollarBrace.ReplaceAllString(inner, "$1")
				}
				if !safe || e.execMode {
					if id, why := e.check(inner, depth+1); id != "" {
						return id, why
					}
				}
				st = st[:rm[2]] + "''" + st[rm[1]:]
			}
			// A. a secrets file read by something that prints
			if on("print-secret-file") {
				files := e.secretFiles(excludeFlag.ReplaceAllString(st, ""))
				if len(files) > 0 && (dumpers.MatchString(quoted.ReplaceAllString(st, "''")) || bareRedirect.MatchString(st)) && !safe && !sedInplace.MatchString(st) {
					return "print-secret-file", "reads " + files[0] + " and prints it"
				}
			}
			// B. echo/printf of a secret-named variable to the terminal
			stB := quoted.ReplaceAllStringFunc(st, func(q string) string {
				if q[0] == '"' {
					return q
				}
				return "''"
			})
			if on("echo-secret-var") {
				for _, m := range echoVar.FindAllStringSubmatchIndex(stB, -1) {
					length := m[6] >= 0
					name := stB[m[8]:m[9]]
					mods := ""
					if m[10] >= 0 {
						mods = stB[m[10]:m[11]]
					}
					if length || strings.Contains(mods, ":+") && mods != "" || !isSecretName(name) {
						continue
					}
					nxt := ""
					hasNext := k+1 < len(pipe)
					if hasNext {
						nxt = cmdWord(pipe[k+1])
					}
					toFile := regexp.MustCompile(`(?:^|[^0-9&])>>?\s*[^&\s]`).MatchString(stB[m[1]:])
					if (!hasNext || display[nxt]) && !toFile && (!safe || e.execMode) {
						return "echo-secret-var", "prints $" + name
					}
				}
			}
			// C. environment dumps
			w := cmdWord(st)
			if on("dump-env") && e.execMode {
				if pe := printenvName.FindStringSubmatch(st); pe != nil && isSecretName(pe[1]) {
					return "dump-env", "printenv " + pe[1] + " prints a secret"
				}
			}
			if on("dump-env") && !safe {
				if w == "printenv" && (len(strings.Fields(st)) == 1 || secretName.MatchString(st)) {
					return "dump-env", "printenv dumps the environment"
				}
				if w == "env" && envAlone.MatchString(st) {
					return "dump-env", "env dumps the environment"
				}
				if dockerExecEnv.MatchString(st) {
					return "dump-env", "env inside a container dumps its environment"
				}
				if pe := printenvName.FindStringSubmatch(st); pe != nil && isSecretName(pe[1]) {
					return "dump-env", "printenv " + pe[1] + " prints a secret"
				}
				if dockerInspect.MatchString(st) {
					fmtF := fmtFlag.MatchString(st)
					nxt := ""
					if k+1 < len(pipe) {
						nxt = cmdWord(pipe[k+1])
					}
					viaTool := (nxt == "jq" || nxt == "python3" || nxt == "python") && !strings.Contains(whole, "Env")
					if fmtF && strings.Contains(st, "Env") || !fmtF && !viaTool {
						return "dump-env", "docker inspect prints Config.Env"
					}
				}
				if (w == "declare" || w == "typeset" || w == "export") && (dumpFlag.MatchString(st) || len(strings.Fields(st)) == 1 || regexp.MustCompile(`^\s*(declare|typeset)\s+-[a-z]*x[a-z]*\s*$`).MatchString(st)) || setAlone.MatchString(st) {
					return "dump-env", "dumping shell variables"
				}
				if h := sysShowHead.FindStringIndex(st); h != nil {
					for _, pm := range sysProp.FindAllStringSubmatch(st[h[1]:], -1) {
						p := pm[1]
						for off := 0; ; {
							i := strings.Index(p[off:], "Environment")
							if i < 0 {
								break
							}
							rest := p[off+i+len("Environment"):]
							if !strings.HasPrefix(rest, "File") {
								return "dump-env", "systemctl show Environment prints environment values"
							}
							off += i + 1
						}
					}
				}
			}
			// E. curl -v prints the request headers, already expanded, to stderr.
			// Not under `safe`: a stdout sink does not cover fd 2. Its escape is 2>/dev/null in the same stage.
			if on("curl-verbose") && w == "curl" && curlVerbose.MatchString(stB) && !stderrNull.MatchString(st) {
				for _, hm := range curlFlagVal.FindAllStringSubmatch(stB, -1) {
					for _, vm := range varRef.FindAllStringSubmatch(hm[1], -1) {
						if isSecretName(vm[1]) {
							return "curl-verbose", "curl -v prints $" + vm[1] + " in clear text on stderr"
						}
					}
				}
			}
			// F. a command sent to the background with a secret expanded in its argv is visible in ps
			if on("background-secret") {
				stOps := quoted.ReplaceAllStringFunc(st, func(q string) string { return strings.Repeat("x", len(q)) })
				for _, bm := range bgOp.FindAllStringSubmatchIndex(stOps, -1) {
					head := singleQ.ReplaceAllString(st[:bm[3]], "''")
					for _, vm := range varRef.FindAllStringSubmatch(head, -1) {
						if isSecretName(vm[1]) {
							return "background-secret", "$" + vm[1] + " stays visible in ps/proc while the background process runs"
						}
					}
				}
			}
		}
	}
	// D. xtrace with secrets in view
	if on("xtrace") && xtrace.MatchString(cmd) {
		hit := len(e.secretFiles(cmd)) > 0
		for _, v := range varRef.FindAllStringSubmatch(cmd, -1) {
			if secretName.MatchString(v[1]) {
				hit = true
			}
		}
		if hit {
			return "xtrace", "set -x / bash -x expands secrets in the trace"
		}
	}
	return "", ""
}

func (e *engine) anyRedactor(s string, perLine bool) bool {
	for _, re := range e.redactors {
		if perLine && anyLine(re, s) || !perLine && re.MatchString(s) {
			return true
		}
	}
	return false
}

func (e *engine) anySafe(s string) bool {
	if e.anyRedactor(s, false) {
		return true
	}
	for _, re := range safeSinks {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// findRemote returns submatch indexes of the earlier-quoted of the two remote forms.
func findRemote(st string) []int {
	a := remoteSQ.FindStringSubmatchIndex(st)
	b := remoteDQ.FindStringSubmatchIndex(st)
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b[2] < a[2]:
		return b
	}
	return a
}

var xargsRe = regexp.MustCompile(`\bxargs\b`)

// xargsRead: `echo .env | xargs cat` - the file name and the reader are in different stages.
func (e *engine) xargsRead(pipe []string, whole string) (string, string) {
	if e.disabled["print-secret-file"] || !xargsRe.MatchString(whole) {
		return "", ""
	}
	if anySafeE(e, whole) {
		return "", ""
	}
	files := e.secretFiles(excludeFlag.ReplaceAllString(whole, ""))
	if len(files) == 0 {
		return "", ""
	}
	for _, st := range pipe {
		if xargsRe.MatchString(st) && dumpers.MatchString(quoted.ReplaceAllString(st, "''")) {
			return "print-secret-file", "passes " + files[0] + " to a reader through xargs"
		}
	}
	return "", ""
}

func anySafeE(e *engine, s string) bool { return e.anySafe(s) }

// stripComments removes shell comments: a # that starts a word, outside quotes,
// to the end of the line. Without this, `docker inspect x # ai-hooks redact`
// would look like it is piped through the redactor.
func stripComments(cmd string) string {
	if !strings.Contains(cmd, "#") {
		return cmd
	}
	var b strings.Builder
	var q byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' && i+1 < len(cmd) {
				b.WriteByte(c)
				i++
				b.WriteByte(cmd[i])
				continue
			}
			if c == q {
				q = 0
			}
		case c == '\\' && i+1 < len(cmd):
			b.WriteByte(c)
			i++
			b.WriteByte(cmd[i])
			continue
		case c == '\'' || c == '"':
			q = c
		case c == '#' && (i == 0 || strings.IndexByte(" \t\n;|&(", cmd[i-1]) >= 0):
			for i < len(cmd) && cmd[i] != '\n' {
				i++
			}
			if i < len(cmd) {
				b.WriteByte('\n')
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
