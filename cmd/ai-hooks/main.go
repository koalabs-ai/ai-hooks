// ai-hooks: keep secrets out of AI coding agent transcripts.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/koalabs-ai/ai-hooks/internal/adapters"
	"github.com/koalabs-ai/ai-hooks/internal/guard"
	"github.com/koalabs-ai/ai-hooks/internal/mcp"
	"github.com/koalabs-ai/ai-hooks/internal/redact"
	"github.com/koalabs-ai/ai-hooks/internal/report"
	"github.com/koalabs-ai/ai-hooks/internal/selftest"
)

var version = "0.1.0-dev"

const usage = `ai-hooks - keep secrets out of AI coding agent transcripts. No network access, no telemetry.

usage:
  ai-hooks redact [--stream] [--cards] [--json] [--report FILE]   stdin -> stdout, secrets become <REDACTED:type:fingerprint>
  ai-hooks guard [-q] [--rules FILE] [--json] [-- COMMAND]        exit 0 allow, 2 block (reason on stderr); command from args or stdin
  ai-hooks exec -- COMMAND [ARGS...]                              guard, run, redact the output, keep the exit code
  ai-hooks scan [--format text|json|sarif] [PATH...]              find secrets in files, directories or stdin (-); exit 1 if any
  ai-hooks hook HARNESS                                           hook entry point (payload on stdin, decision on stdout/exit code)
  ai-hooks install HARNESS [--project] [--dry-run] [--path FILE]  write the minimal hook config (backs up, idempotent)
  ai-hooks uninstall HARNESS [--project] [--dry-run]              remove exactly what install wrote
  ai-hooks config HARNESS                                         print the config install would write
  ai-hooks mcp [--no-run] [--allow-run REGEX]                     MCP server on stdio: guard, redact, scan, safe_run
  ai-hooks shell-init [bash|zsh]                                  print shell functions that route risky commands through exec
  ai-hooks test [--short|--json|--markdown]                       run the bundled corpus: detection and false-alarm rates
  ai-hooks explain [TYPE]                                         what a detector matches (no TYPE: list them)
  ai-hooks rules [list [--json] | schema | validate FILE]        the guard rules and their JSON schema
  ai-hooks version

harnesses: claude, kimi, opencode (verified here); codex, cursor, gemini, copilot, windsurf, devin (from vendor docs, not run)

exit codes: 0 ok / allowed / nothing found; 1 findings (scan) or failed self-test; 2 blocked by the guard or bad usage

environment:
  AI_HOOKS_RULES         guard rules file (default: <config dir>/ai-hooks/rules.json)
  AI_HOOKS_KNOWN_HASHES  file of "sha256 label" lines: values to redact by value
  AI_HOOKS_LOG           override log (default: <state dir>/ai-hooks/overrides.log)
  AI_HOOKS_CARDS=1       also redact payment card numbers (Luhn-checked)
  AI_HOOKS_LANG          message language (only "en" is shipped)
  AI_HOOKS_PARITY=1      compatibility mode: original detector set and names only
`

func main() {
	signal.Ignore(syscall.SIGPIPE) // a closed pipe downstream is not an error for a filter
	if os.Getenv("AI_HOOKS_CARDS") == "1" {
		redact.EnableCards = true
	}
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch args[0] {
	case "redact":
		os.Exit(cmdRedact(args[1:]))
	case "guard":
		os.Exit(cmdGuard(args[1:]))
	case "exec":
		os.Exit(cmdExec(args[1:]))
	case "scan":
		os.Exit(cmdScan(args[1:]))
	case "hook":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ai-hooks hook HARNESS")
			os.Exit(2)
		}
		os.Exit(adapters.Run(args[1], os.Stdin, os.Stdout, os.Stderr))
	case "install", "uninstall":
		os.Exit(cmdInstall(args[0] == "uninstall", args[1:]))
	case "config":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ai-hooks config HARNESS")
			os.Exit(2)
		}
		bin, _ := os.Executable()
		s, ok := adapters.ConfigSnippet(args[1], bin)
		if !ok {
			fmt.Fprintln(os.Stderr, "no config for that harness; known:", harnessList())
			os.Exit(2)
		}
		fmt.Print(s)
	case "mcp":
		os.Exit(cmdMCP(args[1:]))
	case "shell-init":
		os.Exit(cmdShellInit(args[1:]))
	case "test":
		os.Exit(cmdTest(args[1:]))
	case "explain":
		os.Exit(cmdExplain(args[1:]))
	case "rules":
		os.Exit(cmdRules(args[1:]))
	case "version", "--version", "-v":
		fmt.Println("ai-hooks", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	case "--redact-check": // internal: one JSON string per line -> redacted JSON string (parity checker)
		redactCheck()
	case "--guard-check": // internal: one JSON command per line -> "allow" or "block<TAB>rule"
		guardCheck()
	default:
		fmt.Fprintf(os.Stderr, "ai-hooks: unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}
}

func harnessList() string {
	var n []string
	for _, h := range adapters.Harnesses {
		n = append(n, h.Name)
	}
	return strings.Join(n, ", ")
}

func cmdRedact(args []string) int {
	stream, asJSON, report := false, false, ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--stream":
			stream = true
		case "--json":
			asJSON = true
		case "--cards":
			redact.EnableCards = true
		case "--report":
			if i+1 < len(args) {
				i++
				report = args[i]
			}
		default:
			fmt.Fprintln(os.Stderr, "ai-hooks redact: unknown flag", args[i])
			return 2
		}
	}
	known := redact.LoadKnown()
	counts := map[string]int{}
	var out io.Writer = os.Stdout
	if asJSON {
		out = io.Discard
	}
	if stream {
		_ = redact.Stream(os.Stdin, out, known, counts)
	} else {
		data, _ := io.ReadAll(redact.TextReader(os.Stdin))
		if len(data) > 0 {
			text, c := redact.RedactReport(string(data), known)
			for k, v := range c {
				counts[k] = v
			}
			io.WriteString(out, text)
		}
	}
	if asJSON || report != "" {
		b, _ := json.Marshal(reportOf(counts))
		if asJSON {
			fmt.Println(string(b))
		} else if err := os.WriteFile(report, append(b, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "ai-hooks redact:", err)
		}
	}
	return 0 // like the original: a filter never fails the pipeline
}

func reportOf(counts map[string]int) map[string]any {
	total := 0
	for _, v := range counts {
		total += v
	}
	return map[string]any{"redacted": total, "by_type": counts}
}

func readCommand(args []string) string {
	if len(args) > 0 {
		return strings.Join(args, " ")
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	return strings.TrimRight(string(b), "\n")
}

func cmdGuard(args []string) int {
	rules, asJSON, quiet := "", false, false
	for len(args) > 0 {
		switch args[0] {
		case "--rules":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "ai-hooks guard: --rules needs a file")
				return 2
			}
			rules, args = args[1], args[2:]
			continue
		case "--json":
			asJSON = true
			args = args[1:]
			continue
		case "-q", "--quiet":
			quiet = true
			args = args[1:]
			continue
		case "--":
			args = args[1:]
		}
		break
	}
	cmd := readCommand(args)
	var r guard.Result
	if rules != "" {
		var err error
		r, err = guard.CheckWith(cmd, rules)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ai-hooks guard: rules warning:", err)
		}
	} else {
		r = guard.Check(cmd)
	}
	if r.Overridden != "" {
		adapters.LogOverride(cmd, r)
	}
	if asJSON {
		b, _ := json.Marshal(map[string]any{"blocked": r.Blocked, "rule": r.Rule, "detail": r.Detail, "overridden": r.Overridden})
		fmt.Println(string(b))
	}
	if r.Blocked {
		if !asJSON && !quiet {
			fmt.Fprintf(os.Stderr, "ai-hooks [%s]: %s\n", r.Rule, r.Message())
		}
		return 2
	}
	return 0
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`&|;<>()*?[]{}#~!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func cmdExec(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ai-hooks exec -- COMMAND [ARGS...]")
		return 2
	}
	var text string
	var c *exec.Cmd
	if len(args) == 1 {
		text = args[0]
		c = exec.Command("sh", "-c", text)
	} else {
		q := make([]string, len(args))
		for i, a := range args {
			q[i] = shellQuote(a)
		}
		text = strings.Join(q, " ")
		c = exec.Command(args[0], args[1:]...)
	}
	// exec redacts everything the command prints, which satisfies the "pipe it through the redactor" rules
	r := guard.CheckExec(text)
	if r.Overridden != "" {
		adapters.LogOverride(text, r)
	}
	if r.Blocked {
		fmt.Fprintf(os.Stderr, "ai-hooks [%s]: %s\n", r.Rule, r.Message())
		return 2
	}
	known := redact.LoadKnown()
	c.Stdin = os.Stdin
	so, _ := c.StdoutPipe()
	se, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "ai-hooks exec:", err)
		return 127
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); redact.Stream(so, os.Stdout, known, nil) }()
	go func() { defer wg.Done(); redact.Stream(se, os.Stderr, known, nil) }()
	wg.Wait()
	if err := c.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- scan

func cmdScan(args []string) int {
	format := "text"
	var paths []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ai-hooks scan: --format needs text, json or sarif")
				return 2
			}
			i++
			format = args[i]
		case "--json":
			format = "json"
		case "--sarif":
			format = "sarif"
		case "--":
			paths = append(paths, args[i+1:]...)
			i = len(args)
		default:
			paths = append(paths, args[i])
		}
	}
	if format != "text" && format != "json" && format != "sarif" {
		fmt.Fprintln(os.Stderr, "ai-hooks scan: unknown format", format)
		return 2
	}
	if len(paths) == 0 {
		paths = []string{"-"}
	}
	known := redact.LoadKnown()
	var files []report.File
	scanOne := func(name string, r io.Reader) {
		f, _ := redact.Scan(r, known)
		files = append(files, report.File{Path: name, Findings: f})
	}
	rc := 0
	for _, p := range paths {
		if p == "-" {
			scanOne("<stdin>", redact.TextReader(os.Stdin))
			continue
		}
		st, err := os.Lstat(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ai-hooks scan:", err)
			rc = 2
			continue
		}
		if !st.IsDir() {
			scanFile(p, scanOne)
			continue
		}
		filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() { // never follow links out of the tree
				return nil
			}
			scanFile(path, scanOne)
			return nil
		})
	}
	var err error
	switch format {
	case "json":
		err = report.JSON(os.Stdout, files)
	case "sarif":
		err = report.SARIF(os.Stdout, files, version)
	default:
		report.Text(os.Stdout, files)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-hooks scan:", err)
		return 2
	}
	for _, f := range files {
		if len(f.Findings) > 0 && rc == 0 {
			return 1
		}
	}
	return rc
}

func scanFile(path string, scanOne func(string, io.Reader)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	for _, b := range head[:n] {
		if b == 0 { // binary
			return
		}
	}
	f.Seek(0, io.SeekStart)
	scanOne(path, io.LimitReader(redact.TextReader(f), 64<<20))
}

// ---------------------------------------------------------------- install, mcp, shell-init

func cmdInstall(remove bool, args []string) int {
	o := adapters.InstallOptions{Remove: remove}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--project":
			o.Project = true
		case "--dry-run":
			o.DryRun = true
		case "--path":
			if i+1 < len(args) {
				i++
				o.Path = args[i]
			}
		case "--bin":
			if i+1 < len(args) {
				i++
				o.Bin = args[i]
			}
		default:
			if o.Harness == "" && !strings.HasPrefix(args[i], "-") {
				o.Harness = args[i]
			} else {
				fmt.Fprintln(os.Stderr, "ai-hooks: unknown argument", args[i])
				return 2
			}
		}
	}
	if o.Harness == "" {
		fmt.Fprintln(os.Stderr, "usage: ai-hooks install|uninstall HARNESS [--project] [--dry-run] [--path FILE]; harnesses:", harnessList())
		return 2
	}
	msgs, err := adapters.Install(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ai-hooks:", err)
		return 1
	}
	prefix := ""
	if o.DryRun {
		prefix = "(dry run) would have: "
	}
	for _, m := range msgs {
		fmt.Println(prefix + m)
	}
	if !remove && !o.DryRun {
		fmt.Println("Done. Restart the agent so it reads the new config. Undo with: ai-hooks uninstall " + o.Harness)
	}
	return 0
}

func cmdMCP(args []string) int {
	o := mcp.Options{Version: version}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-run":
			o.NoRun = true
		case "--allow-run":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ai-hooks mcp: --allow-run needs a regular expression")
				return 2
			}
			i++
			re, err := regexp.Compile(args[i])
			if err != nil {
				fmt.Fprintln(os.Stderr, "ai-hooks mcp: bad --allow-run:", err)
				return 2
			}
			o.Allow = append(o.Allow, re)
		default:
			fmt.Fprintln(os.Stderr, "ai-hooks mcp: unknown flag", args[i])
			return 2
		}
	}
	if err := mcp.Serve(os.Stdin, os.Stdout, o); err != nil {
		fmt.Fprintln(os.Stderr, "ai-hooks mcp:", err)
		return 1
	}
	return 0
}

// the commands a shell shim wraps: readers of files and printers of credentials
var shimCommands = []string{"cat", "less", "more", "head", "tail", "bat", "strings", "xxd", "od", "nl", "tac",
	"journalctl", "systemctl", "docker", "docker-compose", "kubectl", "aws", "gcloud", "az", "gh", "git",
	"terraform", "tofu", "pulumi", "vault", "op", "bw", "pass", "gopass", "sops", "doppler", "heroku", "printenv"}

func cmdShellInit(args []string) int {
	sh := "bash"
	if len(args) > 0 {
		sh = args[0]
	}
	if sh != "bash" && sh != "zsh" {
		fmt.Fprintln(os.Stderr, "usage: ai-hooks shell-init [bash|zsh]")
		return 2
	}
	fmt.Print(`# ai-hooks shell integration (` + sh + `). Source it, or point BASH_ENV at it for non-interactive shells:
#   ai-hooks shell-init ` + sh + ` > ~/.config/ai-hooks/shell.sh && export BASH_ENV=~/.config/ai-hooks/shell.sh
# A wrapped command that the guard would block runs through "ai-hooks exec" instead, so its output is redacted.
__aihooks() {
  local _name=$1; shift
  if ! command -v ai-hooks >/dev/null 2>&1; then command "$_name" "$@"; return; fi
  local _line
  _line=$(printf '%q ' "$_name" "$@")
  if command ai-hooks guard --quiet -- "$_line"; then
    command "$_name" "$@"
  else
    command ai-hooks exec -- "$_name" "$@"
  fi
}
`)
	for _, c := range shimCommands {
		fmt.Printf("%s() { __aihooks %s \"$@\"; }\n", c, c)
	}
	return 0
}

// ---------------------------------------------------------------- test, explain, rules

func cmdTest(args []string) int {
	r := selftest.Run()
	if len(args) > 0 && args[0] == "--short" {
		fmt.Printf("detection          %d/%d secrets redacted\n", r.Detected, r.Total)
		fmt.Printf("false alarms       %d/%d clean samples touched\n", r.FalseAlarms, r.NegTotal)
		fmt.Printf("known misses       %d (listed by `ai-hooks test`)\n", len(r.KnownMisses))
		fmt.Printf("known false alarms %d (listed by `ai-hooks test`)\n", len(r.KnownFalseAlarms))
	} else if len(args) > 0 && args[0] == "--markdown" {
		r.Markdown(os.Stdout)
	} else if len(args) > 0 && args[0] == "--json" {
		b, _ := json.Marshal(map[string]any{
			"detected": r.Detected, "total": r.Total, "by_type": r.ByType,
			"false_alarms": r.FalseAlarms, "negatives": r.NegTotal,
			"missed": r.Missed, "known_misses": r.KnownMisses, "known_false_alarms": r.KnownFalseAlarms,
		})
		fmt.Println(string(b))
	} else {
		r.Print(os.Stdout)
	}
	if !r.OK() {
		return 1
	}
	return 0
}

func cmdExplain(args []string) int {
	markdown := false
	if len(args) > 0 && args[0] == "--markdown" {
		markdown, args = true, args[1:]
	}
	if len(args) == 0 {
		if markdown {
			fmt.Println("| Detector | What it matches |\n|---|---|")
		}
		for _, t := range redact.Types() {
			d, _ := redact.Explain(t)
			if markdown {
				fmt.Printf("| `%s` | %s |\n", t, strings.ReplaceAll(d, "|", "\\|"))
			} else {
				fmt.Printf("%-34s %s\n", t, d)
			}
		}
		return 0
	}
	d, ok := redact.Explain(args[0])
	if !ok {
		types := redact.Types()
		sort.Strings(types)
		fmt.Fprintf(os.Stderr, "unknown type %q; known: %s\n", args[0], strings.Join(types, ", "))
		return 1
	}
	fmt.Println(d)
	return 0
}

func cmdRules(args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "":
		os.Stdout.Write(guard.DefaultRulesJSON())
	case "schema":
		os.Stdout.Write(guard.SchemaJSON())
	case "validate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ai-hooks rules validate FILE")
			return 2
		}
		if errs := guard.ValidateFile(args[1]); len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, "invalid:", e)
			}
			return 1
		}
		fmt.Println("ok")
	case "list":
		asJSON := len(args) > 1 && args[1] == "--json"
		return listRules(asJSON)
	default:
		fmt.Fprintln(os.Stderr, "usage: ai-hooks rules [list [--json] | schema | validate FILE]")
		return 2
	}
	return 0
}

func listRules(asJSON bool) int {
	type item struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Why  string `json:"why"`
	}
	var items []item
	for _, r := range guard.Rules() {
		items = append(items, item{r.ID, r.Kind, r.Why})
	}
	var dets []map[string]string
	for _, t := range redact.Types() {
		d, _ := redact.Explain(t)
		dets = append(dets, map[string]string{"id": t, "description": d})
	}
	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{"version": version, "guard_rules": items, "detectors": dets, "aliases": redact.Aliases}, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Println("guard rules:")
	for _, i := range items {
		fmt.Printf("  %-26s [%s] %s\n", i.ID, i.Kind, i.Why)
	}
	fmt.Printf("detectors: %d (see `ai-hooks explain`)\n", len(dets))
	return 0
}

func redactCheck() {
	known := redact.LoadKnown()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	w := bufio.NewWriter(os.Stdout)
	for sc.Scan() {
		var in string
		if json.Unmarshal(sc.Bytes(), &in) != nil {
			fmt.Fprintln(w, "null")
			continue
		}
		b, _ := json.Marshal(redact.Redact(in, known))
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
}

func guardCheck() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var cmd string
		if json.Unmarshal(sc.Bytes(), &cmd) != nil {
			cmd = sc.Text()
		}
		r := guard.Check(cmd)
		if r.Blocked {
			fmt.Printf("block\t%s\n", r.Rule)
		} else {
			fmt.Println("allow")
		}
	}
}
