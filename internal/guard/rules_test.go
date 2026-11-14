package guard

import "testing"

func TestCommonSecretPrintingCommands(t *testing.T) {
	block := map[string]string{
		"cat /proc/1/environ":                                        "proc-environ",
		"strings /proc/self/environ":                                 "proc-environ",
		"ps eww -p 1":                                                "ps-environment",
		"ps auxe":                                                    "ps-environment",
		"docker compose config":                                      "docker-compose-config",
		"docker-compose -f x.yml config":                             "docker-compose-config",
		"kubectl config view --raw":                                  "kubectl-config-raw",
		"kubectl exec pod-1 -- env":                                  "env-dump",
		"aws configure export-credentials":                           "aws-print-credentials",
		"aws secretsmanager get-secret-value --secret-id db":         "aws-print-credentials",
		"aws ssm get-parameter --name x --with-decryption":           "aws-print-credentials",
		"aws ecr get-login-password":                                 "aws-print-credentials",
		"gcloud auth print-access-token":                             "gcloud-print-token",
		"gcloud secrets versions access latest --secret=x":           "gcloud-print-token",
		"az account get-access-token":                                "azure-print-credentials",
		"az keyvault secret show --name x --vault-name y":            "azure-print-credentials",
		"gh auth token":                                              "gh-print-token",
		"gh auth status --show-token":                                "gh-print-token",
		"git config --list":                                          "git-config-list",
		"git config --global -l":                                     "git-config-list",
		"git credential fill":                                        "git-config-list",
		"cat ~/.aws/credentials":                                     "read-credential-file",
		"cat ~/.netrc":                                               "read-credential-file",
		"less ~/.npmrc":                                              "read-credential-file",
		"cat ~/.docker/config.json":                                  "read-credential-file",
		"jq . ~/.config/gcloud/application_default_credentials.json": "read-credential-file",
		"cat ~/.ssh/id_ed25519":                                      "read-credential-file",
		"cat infra/terraform.tfstate":                                "read-credential-file",
		"cat ~/.bash_history":                                        "shell-history",
		"grep token ~/.zsh_history":                                  "shell-history",
		"history":                                                    "shell-history",
		"history | tail -50":                                         "shell-history",
		"terraform output":                                           "terraform-output",
		"terraform show -json":                                       "terraform-output",
		"tofu state pull":                                            "terraform-output",
		"vault kv get secret/app":                                    "secret-manager-read",
		"op read op://vault/item/password":                           "secret-manager-read",
		"bw get password github":                                     "secret-manager-read",
		"pass show email/work":                                       "secret-manager-read",
		"sops -d secrets.yaml":                                       "secret-manager-read",
		"heroku config":                                              "secret-manager-read",
		"npm config get //registry.npmjs.org/:_authToken":            "secret-manager-read",
		"headscale preauthkeys create --user 1":                      "headscale-key",
		"python3 -c 'import os; print(dict(os.environ))'":            "script-env-dump",
		"node -e 'console.log(JSON.stringify(process.env))'":         "script-env-dump",
		"ssh host 'cat ~/.aws/credentials'":                          "read-credential-file",
	}
	allow := []string{
		"cat ~/.ssh/id_ed25519.pub",
		"cat ~/.ssh/known_hosts",
		"git config user.email",
		"git config --get remote.origin.url",
		"git status",
		"docker compose up -d",
		"docker compose ps",
		"kubectl get pods",
		"kubectl config current-context",
		"aws s3 ls",
		"aws sts get-caller-identity",
		"gcloud config list",
		"gh auth status",
		"gh pr list",
		"terraform plan",
		"terraform validate",
		"ps aux",
		"ps -ef",
		"python3 -c 'print(1+1)'",
		"node -e 'console.log(process.env.HOME)'",
		"cat README.md",
		"cat .env.example",
		"echo history is a word",
		"vault status",
		"pass ls",
		"ls ~/.aws",
		"cat ~/.aws/credentials | ai-hooks redact",
		"terraform output 2>&1 | ai-hooks redact",
	}
	e := newTestEngine(t)
	for cmd, want := range block {
		r := e.decide(cmd, false)
		if !r.Blocked || r.Rule != want {
			t.Errorf("%q: blocked=%v rule=%q want %q", cmd, r.Blocked, r.Rule, want)
		}
	}
	for _, cmd := range allow {
		if r := e.decide(cmd, false); r.Blocked {
			t.Errorf("%q should pass, blocked by %s", cmd, r.Rule)
		}
	}
}
