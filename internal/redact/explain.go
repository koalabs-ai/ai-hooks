package redact

// Explain returns a one-line description of what a detector type matches.
func Explain(t string) (string, bool) {
	if d, ok := descriptions[t]; ok {
		return d, true
	}
	if d, ok := descriptions[Canonical(t)]; ok {
		return d, true
	}
	d, ok := extraDescriptions()[t]
	return d, ok
}

var descriptions = map[string]string{
	"known":                "A value whose sha256 is in your known-hashes file (AI_HOOKS_KNOWN_HASHES). Reported as known-<label>.",
	"stripe-live":          "Stripe live secret key: sk_live_ followed by 20+ characters.",
	"stripe-test":          "Stripe test secret key: sk_test_ followed by 20+ characters.",
	"stripe-restricted":    "Stripe restricted key: rk_live_ or rk_test_ followed by 20+ characters.",
	"stripe-publishable":   "Stripe publishable key: pk_live_ or pk_test_ followed by 20+ characters.",
	"github-pat":           "GitHub token: ghp_, gho_, ghr_, ghs_ or ghu_ followed by 20+ alphanumerics.",
	"github-fine-pat":      "GitHub fine-grained personal access token: github_pat_ followed by 20+ characters.",
	"gitlab-pat":           "GitLab personal access token: glpat- followed by 20+ characters.",
	"supabase-secret":      "Supabase secret key: sb_secret_ followed by 16+ characters.",
	"supabase-publishable": "Supabase publishable key: sb_publishable_ followed by 16+ characters.",
	"resend":               "Resend API key: re_<id>_<secret>.",
	"forgejo-pat":          "Forgejo/Gitea token: forgejo_ or gitea_ followed by 40 hex digits.",
	"forgejo-token":        "A 40-hex value labelled token (Forgejo/Gitea/Git hosting API tokens). Only the value is replaced.",
	"aws-key-id":           "AWS access key id: AKIA followed by 16 upper-case letters or digits.",
	"aws-secret":           "AWS secret access key: 40 base64 characters after aws_secret_access_key. Only the value is replaced.",
	"google-api":           "Google API key: AIza followed by 35+ characters.",
	"zai-api":              "Z.ai style API key: 32 hex digits, a dot, then 15+ characters.",
	"anthropic":            "Anthropic API key: sk-ant- followed by 20+ characters.",
	"openai":               "OpenAI style API key: sk- (or sk-proj-) followed by 20+ characters.",
	"slack-bot":            "Slack token: xoxa-, xoxb-, xoxp-, xoxr- or xoxs- followed by 10+ characters.",
	"chatwoot-bot-token":   "Chatwoot access token: a 24-character token after a chatwoot/api access token label. Only the value is replaced.",
	"twilio-sid-secret":    "Twilio API key secret: SK followed by 32 hex digits.",
	"twilio-auth-hex":      "A bare 32-hex value followed by a delimiter (Twilio auth token shape). Skipped when the same line names an invocation id, md5, checksum, etag, trace id or similar. The most ambiguous detector: expect false alarms on bare md5 sums.",
	"telegram-bot":         "Telegram bot token: 8-12 digits, a colon, then 30+ characters.",
	"mp-token":             "Mercado Pago access token: APP_USR- followed by 20+ characters.",
	"mp-access-test":       "Mercado Pago test access token: TEST-<digits>-<digits>-<32 hex>-<digits>.",
	"jwt":                  "JSON Web Token: three dot-separated base64url parts, the first two starting with eyJ.",
	"bearer":               "Value of a Bearer authorization scheme (20+ characters). Only the value is replaced.",
	"basic-auth":           "Value of a Basic authorization scheme (20+ base64 characters). Only the value is replaced.",
	"http-secret-header":   "Value of an x-api-key, x-auth-token or authorization header. Only the value is replaced.",
	"uri-credentials":      "Password inside a URL: scheme://user:PASSWORD@host. Only the password is replaced.",
	"libpq-password":       "Password in a PostgreSQL connection string or PGPASSWORD assignment. Only the value is replaced.",
	"env-secret-hex":       "NAME=<24+ hex digits> where NAME contains SECRET, TOKEN, PASSWORD, KEY-type words. Only the value is replaced.",
	"env-secret-token":     "NAME=<20+ token characters> where NAME contains SECRET, TOKEN, PASSWORD, KEY-type words. Only the value is replaced.",
	"label-secret-hex":     "A label such as secret key, api key or clave followed by = or : and 20+ hex digits.",
	"label-secret-token":   "A label such as secret, token, password or api key followed by a quoted 20+ character value.",
	"pem":                  "A PEM private key block, from the BEGIN line to the END line.",
}
