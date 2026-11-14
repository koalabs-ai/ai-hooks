package redact

// Public detector names: kebab-case, vendor-product-kind. The first version used
// shorter internal names; Aliases maps each old name to its public one so that
// output, reports and rules written against the old names can be translated.
// AI_HOOKS_PARITY=1 emits the old names (the byte-identical mode).

// Aliases maps the original detector names to the public names.
var Aliases = map[string]string{
	"stripe-live":          "stripe-secret-key-live",
	"stripe-test":          "stripe-secret-key-test",
	"stripe-restricted":    "stripe-restricted-key",
	"stripe-publishable":   "stripe-publishable-key",
	"github-pat":           "github-token",
	"github-fine-pat":      "github-fine-grained-token",
	"gitlab-pat":           "gitlab-personal-token",
	"supabase-secret":      "supabase-secret-key",
	"supabase-publishable": "supabase-publishable-key",
	"resend":               "resend-api-key",
	"forgejo-pat":          "forgejo-token",
	"forgejo-token":        "git-host-api-token",
	"aws-key-id":           "aws-access-key",
	"aws-secret":           "aws-secret-key",
	"google-api":           "google-api-key",
	"zai-api":              "zai-api-key",
	"anthropic":            "anthropic-api-key",
	"openai":               "openai-api-key",
	"slack-bot":            "slack-token",
	"chatwoot-bot-token":   "chatwoot-access-token",
	"twilio-sid-secret":    "twilio-api-key-secret",
	"twilio-auth-hex":      "twilio-auth-token",
	"telegram-bot":         "telegram-bot-token",
	"mp-token":             "mercadopago-access-token",
	"mp-access-test":       "mercadopago-test-token",
	"jwt":                  "jwt",
	"bearer":               "bearer-token",
	"basic-auth":           "basic-auth-credentials",
	"http-secret-header":   "http-auth-header",
	"uri-credentials":      "url-password",
	"libpq-password":       "postgres-password",
	"env-secret-hex":       "env-secret-hex",
	"env-secret-token":     "env-secret",
	"label-secret-hex":     "labelled-secret-hex",
	"label-secret-token":   "labelled-secret",
	"pem":                  "private-key-pem",
}

var reverse map[string]string

// Display is the name a detector reports under (the old name in parity mode).
func Display(kind string) string {
	if Parity {
		return kind
	}
	if n, ok := Aliases[kind]; ok {
		return n
	}
	return kind
}

// Canonical turns a public or old name into the internal (old) name, for lookups.
func Canonical(name string) string {
	if reverse == nil {
		reverse = map[string]string{}
		for o, n := range Aliases {
			reverse[n] = o
		}
	}
	if o, ok := reverse[name]; ok {
		return o
	}
	return name
}
