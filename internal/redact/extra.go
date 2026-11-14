package redact

// Extra detectors: provider token formats and generic structures added after the
// original port. They are written from the public, documented shapes of each
// token (prefix, length, alphabet); no rule file from another project is copied.
//
// They run BEFORE the original detectors, so a token with a distinctive prefix
// is reported under its own type instead of a generic one. AI_HOOKS_PARITY=1
// switches all of them off, which gives output byte-identical to the original.

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

type extra struct {
	kind      string
	desc      string
	pattern   string
	group     int
	tailed    bool
	ci        bool     // pattern is (?i): use the case-insensitive word-start check
	needs     []string // the text must contain one of these (lower-case when fold) or the pattern is skipped
	fold      bool
	multiline bool
}

var extras = []extra{
	// ---- cloud
	{kind: "gcp-oauth-client-secret", desc: "Google OAuth client secret: GOCSPX- followed by 28 characters.", pattern: `GOCSPX-[A-Za-z0-9_-]{28,}`, needs: []string{"GOCSPX-"}},
	{kind: "gcp-service-account-key-id", desc: "Google Cloud service-account key id in JSON: private_key_id with 40 hex digits. The private_key itself is caught as a PEM block.", pattern: `(?i)"private_key_id"[ \t]*:[ \t]*"([a-f0-9]{40})"`, group: 1, ci: true, needs: []string{"private_key_id"}, fold: true},
	{kind: "aws-temporary-access-key", desc: "AWS temporary access key id: ASIA followed by 16 upper-case letters or digits.", pattern: `ASIA[0-9A-Z]{16}([^\p{L}\p{N}_]|$)`, tailed: true, needs: []string{"ASIA"}},
	{kind: "aws-session-token", desc: "AWS session token (100+ base64 characters) after aws_session_token. Only the value is replaced.", pattern: `(?i)aws_session_token["'\s=:]+([A-Za-z0-9/+=]{100,})`, group: 1, ci: true, needs: []string{"aws_session_token"}, fold: true},
	{kind: "azure-storage-account-key", desc: "Azure AccountKey/SharedAccessKey/PrimaryKey value (base64, 40+ characters) in a connection string. Only the value is replaced.", pattern: `(?i)(?:AccountKey|SharedAccessKey|PrimaryKey|SecondaryKey)=([A-Za-z0-9+/]{40,}={0,2})`, group: 1, ci: true, needs: []string{"accountkey=", "sharedaccesskey=", "primarykey=", "secondarykey="}, fold: true},
	{kind: "azure-sas-token", desc: "Azure shared-access-signature: the sig= query parameter (40+ characters). Only the value is replaced.", pattern: `[?&]sig=([A-Za-z0-9%+/=]{40,})`, group: 1, needs: []string{"sig="}},
	{kind: "azure-client-secret", desc: "Azure AD client secret: 3 characters, a digit, Q~, then 31 to 34 characters.", pattern: `[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`, needs: []string{"Q~"}},
	{kind: "digitalocean-token", desc: "DigitalOcean token: dop_v1_, doo_v1_ or dor_v1_ followed by 64 hex digits.", pattern: `do[por]_v1_[a-f0-9]{64}`, needs: []string{"_v1_"}},
	{kind: "cloudflare-api-token", desc: "Cloudflare scannable token: cfut_, cfk_ or cfat_ followed by 40+ characters.", pattern: `cf(?:ut|k|at)_[A-Za-z0-9]{40,}`, needs: []string{"cfut_", "cfk_", "cfat_"}},
	{kind: "cloudflare-api-key", desc: "Cloudflare API key or token (37 to 40 characters) after a cloudflare ... key/token label. Only the value is replaced.", pattern: `(?i)cloudflare[\w ._-]{0,24}(?:token|key)["'\s:=]+([A-Za-z0-9_-]{37,40})`, group: 1, ci: true, needs: []string{"cloudflare"}, fold: true},
	{kind: "hetzner-api-token", desc: "Hetzner Cloud API token (64 characters) after an hcloud/hetzner token label. Only the value is replaced.", pattern: `(?i)(?:hcloud|hetzner)[\w ._-]{0,24}(?:token|key)["'\s:=]+([A-Za-z0-9]{64})`, group: 1, ci: true, needs: []string{"hcloud", "hetzner"}, fold: true},
	// ---- AI providers
	{kind: "openrouter-api-key", desc: "OpenRouter API key: sk-or-v1- followed by 64 hex digits.", pattern: `sk-or-v1-[a-f0-9]{64}`, needs: []string{"sk-or-"}},
	{kind: "openai-service-key", desc: "OpenAI service-account or admin key: sk-svcacct- or sk-admin- followed by 20+ characters.", pattern: `sk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}`, needs: []string{"sk-svcacct-", "sk-admin-"}},
	{kind: "huggingface-token", desc: "Hugging Face token: hf_ followed by 34+ letters and digits.", pattern: `hf_[A-Za-z0-9]{34,}`, needs: []string{"hf_"}},
	{kind: "replicate-api-token", desc: "Replicate API token: r8_ followed by 37 letters and digits.", pattern: `r8_[A-Za-z0-9]{37,}`, tailed: false, needs: []string{"r8_"}},
	{kind: "groq-api-key", desc: "Groq API key: gsk_ followed by 52 letters and digits.", pattern: `gsk_[A-Za-z0-9]{52,}`, needs: []string{"gsk_"}},
	{kind: "perplexity-api-key", desc: "Perplexity API key: pplx- followed by 48 letters and digits.", pattern: `pplx-[A-Za-z0-9]{48,}`, needs: []string{"pplx-"}},
	{kind: "xai-api-key", desc: "xAI API key: xai- followed by 80 letters and digits.", pattern: `xai-[A-Za-z0-9]{80,}`, needs: []string{"xai-"}},
	{kind: "elevenlabs-api-key", desc: "ElevenLabs API key: sk_ followed by 48 hex digits.", pattern: `sk_[a-f0-9]{48}`, needs: []string{"sk_"}},
	{kind: "nvidia-api-key", desc: "NVIDIA API key: nvapi- followed by 60+ characters.", pattern: `nvapi-[A-Za-z0-9_-]{60,}`, needs: []string{"nvapi-"}},
	{kind: "langsmith-api-key", desc: "LangSmith API key: lsv2_pt_ or lsv2_sk_ followed by 32 hex digits, an underscore and 10 hex digits.", pattern: `lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}`, needs: []string{"lsv2_"}},
	{kind: "together-ai-key", desc: "Together AI key: tgp_v1_ followed by 40+ characters.", pattern: `tgp_v1_[A-Za-z0-9_-]{40,}`, needs: []string{"tgp_v1_"}},
	{kind: "llm-provider-key", desc: "A Mistral, Cohere, DeepSeek, Fireworks or Together key (32 to 40 characters, no prefix) after a provider-named key label. Only the value is replaced.", pattern: `(?i)(?:mistral|cohere|fireworks|together|voyage|jina)[\w ._-]{0,24}(?:api[_ -]?)?(?:key|token)["'\s:=]+([A-Za-z0-9]{32,40})`, group: 1, ci: true, needs: []string{"mistral", "cohere", "fireworks", "together", "voyage", "jina"}, fold: true},
	// ---- code hosts and registries
	{kind: "gitlab-token", desc: "GitLab token of a kind other than glpat-: gldt-, glrt-, glcbt-, glptt-, glft-, glimt-, glagent-, gloas-, glsoat- followed by 20+ characters.", pattern: `gl(?:dt|rt|cbt|ptt|ft|imt|agent|oas|soat)-[A-Za-z0-9_-]{20,}`, needs: []string{"gldt-", "glrt-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "gloas-", "glsoat-"}},
	{kind: "atlassian-token", desc: "Bitbucket/Atlassian token: ATBB or ATATT3 followed by 30+ characters.", pattern: `AT(?:BB|ATT3)[A-Za-z0-9_=.-]{30,}`, needs: []string{"ATBB", "ATATT3"}},
	{kind: "npm-access-token", desc: "npm access token: npm_ followed by 36 letters and digits.", pattern: `npm_[A-Za-z0-9]{36,}`, needs: []string{"npm_"}},
	{kind: "npm-auth", desc: "An _authToken or _password line of an .npmrc. Only the value is replaced.", pattern: `(?im)(?:^|[:/])_(?:authToken|auth|password)[ \t]*=[ \t]*["']?([^\s"']{8,})`, group: 1, ci: true, needs: []string{"_auth", "_password"}, fold: true},
	{kind: "pypi-api-token", desc: "PyPI upload token: pypi-AgEIcHlwaS5vcmc followed by 50+ characters.", pattern: `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`, needs: []string{"pypi-AgEI"}},
	{kind: "crates-io-token", desc: "crates.io token: cio followed by 32 letters and digits.", pattern: `cio[A-Za-z0-9]{32}([^\p{L}\p{N}_]|$)`, tailed: true, needs: []string{"cio"}},
	{kind: "rubygems-api-key", desc: "RubyGems API key: rubygems_ followed by 48 hex digits.", pattern: `rubygems_[a-f0-9]{48}`, needs: []string{"rubygems_"}},
	{kind: "dockerhub-token", desc: "Docker Hub personal access token: dckr_pat_ followed by 27+ characters.", pattern: `dckr_pat_[A-Za-z0-9_-]{27,}`, needs: []string{"dckr_pat_"}},
	{kind: "docker-registry-auth", desc: "The base64 user:password in a Docker config.json auth entry. Only the value is replaced.", pattern: `"auth"[ \t]*:[ \t]*"([A-Za-z0-9+/=]{20,})"`, group: 1, needs: []string{`"auth"`}},
	// ---- payments
	{kind: "stripe-webhook-secret", desc: "Stripe webhook signing secret: whsec_ followed by 24+ characters.", pattern: `whsec_[A-Za-z0-9]{24,}`, needs: []string{"whsec_"}},
	{kind: "braintree-access-token", desc: "Braintree/PayPal access token: access_token$production$<16>$<32 hex>.", pattern: `access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}`, needs: []string{"access_token$"}},
	{kind: "square-access-token", desc: "Square token: sq0atp- or sq0csp- followed by 22 to 43 characters, or EAAA followed by 60 characters.", pattern: `(?:sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}|EAAA[A-Za-z0-9_-]{60})`, needs: []string{"sq0", "EAAA"}},
	{kind: "shopify-access-token", desc: "Shopify token: shpat_, shpca_, shppa_ or shpss_ followed by 32 hex digits.", pattern: `shp(?:at|ca|pa|ss)_[a-f0-9]{32}`, needs: []string{"shp"}},
	// ---- communication
	{kind: "slack-app-token", desc: "Slack app-level or config token: xapp-<n>-... or xoxe.xox?-<n>-... (long).", pattern: `(?:xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{40,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]{100,})`, needs: []string{"xapp-", "xoxe"}},
	{kind: "slack-webhook-url", desc: "Slack incoming webhook URL (hooks.slack.com/services/T.../B.../...).", pattern: `https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}`, needs: []string{"hooks.slack.com"}},
	{kind: "discord-webhook-url", desc: "Discord webhook URL with its token.", pattern: `https://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,}`, needs: []string{"/api/webhooks/"}},
	{kind: "discord-bot-token", desc: "Discord bot token: three dot-separated parts starting with M, N or O.", pattern: `[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}`, needs: []string{"."}},
	{kind: "sendgrid-api-key", desc: "SendGrid API key: SG. followed by 22 characters, a dot and 43 characters.", pattern: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`, needs: []string{"SG."}},
	{kind: "mailgun-api-key", desc: "Mailgun API key: key- followed by 32 hex digits.", pattern: `key-[a-f0-9]{32}([^\p{L}\p{N}_]|$)`, tailed: true, needs: []string{"key-"}},
	{kind: "mailchimp-api-key", desc: "Mailchimp API key: 32 hex digits, a dash and a data-centre suffix such as us12.", pattern: `[a-f0-9]{32}-us\d{1,2}([^\p{L}\p{N}_]|$)`, tailed: true, needs: []string{"-us"}},
	// ---- platforms and developer services
	{kind: "sentry-auth-token", desc: "Sentry auth token: sntrys_ (40+ characters) or sntryu_ followed by 64 hex digits.", pattern: `(?:sntrys_[A-Za-z0-9+/=_-]{40,}|sntryu_[a-f0-9]{64})`, needs: []string{"sntry"}},
	{kind: "newrelic-api-key", desc: "New Relic key: NRAK-, NRII- or NRJS- followed by 27 to 32 characters.", pattern: `NR(?:AK|II|JS)-[A-Z0-9]{27,32}`, needs: []string{"NRAK-", "NRII-", "NRJS-"}},
	{kind: "netlify-access-token", desc: "Netlify personal access token: nfp_ followed by 36 characters.", pattern: `nfp_[A-Za-z0-9]{36}`, needs: []string{"nfp_"}},
	{kind: "flyio-token", desc: "Fly.io token: fo1_, fm1r_ or fm1a_ followed by 40+ characters.", pattern: `f(?:o1|m1[ra])_[A-Za-z0-9_+/=-]{40,}`, needs: []string{"fo1_", "fm1r_", "fm1a_"}},
	{kind: "heroku-api-key", desc: "Heroku API key: HRKU- followed by 60+ characters.", pattern: `HRKU-[A-Za-z0-9_-]{60,}`, needs: []string{"HRKU-"}},
	{kind: "supabase-access-token", desc: "Supabase personal access token: sbp_ followed by 40 hex digits.", pattern: `sbp_[a-f0-9]{40}`, needs: []string{"sbp_"}},
	{kind: "planetscale-token", desc: "PlanetScale token: pscale_tkn_, pscale_pw_ or pscale_oauth_ followed by 32+ characters.", pattern: `pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_-]{32,}`, needs: []string{"pscale_"}},
	{kind: "linear-api-key", desc: "Linear API key: lin_api_ followed by 40 characters.", pattern: `lin_api_[A-Za-z0-9]{40,}`, needs: []string{"lin_api_"}},
	{kind: "notion-token", desc: "Notion integration token: ntn_ followed by 40+ characters, or secret_ followed by 43.", pattern: `(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})`, needs: []string{"ntn_", "secret_"}},
	{kind: "airtable-token", desc: "Airtable personal access token: pat, 14 characters, a dot and 64 hex digits.", pattern: `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`, needs: []string{"pat"}},
	{kind: "doppler-token", desc: "Doppler token: dp.pt., dp.st., dp.sa., dp.ct. followed by 40+ characters.", pattern: `dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}`, needs: []string{"dp."}},
	{kind: "onepassword-service-account-token", desc: "1Password service-account token: ops_eyJ followed by 100+ characters.", pattern: `ops_eyJ[A-Za-z0-9+/=_-]{100,}`, needs: []string{"ops_eyJ"}},
	{kind: "hashicorp-vault-token", desc: "HashiCorp Vault token: hvs., hvb. or hvr. followed by 24+ characters.", pattern: `hv[sbr]\.[A-Za-z0-9_-]{24,}`, needs: []string{"hvs.", "hvb.", "hvr."}},
	{kind: "terraform-cloud-token", desc: "Terraform Cloud/Enterprise token: 14 characters, .atlasv1. and 60+ characters.", pattern: `[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}`, needs: []string{".atlasv1."}},
	{kind: "pulumi-access-token", desc: "Pulumi access token: pul- followed by 40 hex digits.", pattern: `pul-[a-f0-9]{40}`, needs: []string{"pul-"}},
	// ---- network and keys
	{kind: "tailscale-key", desc: "Tailscale auth, API or client key: tskey-auth-, tskey-api-, tskey-client-... followed by an id and a secret.", pattern: `tskey-(?:auth|api|client|scim|webhook)-[A-Za-z0-9]+-[A-Za-z0-9]{20,}`, needs: []string{"tskey-"}},
	{kind: "headscale-preauth-key", desc: "A 48-hex Headscale pre-auth key after a preauth/authkey label or flag. Only the value is replaced.", pattern: `(?i)(?:pre-?auth|auth-?key)[\w ._-]{0,16}["'\s:=]+([a-f0-9]{48})([^\p{L}\p{N}_]|$)`, group: 1, tailed: true, ci: true, needs: []string{"preauth", "pre-auth", "authkey", "auth-key", "auth_key"}, fold: true},
	{kind: "wireguard-private-key", desc: "A WireGuard PrivateKey = line (44 base64 characters). Only the value is replaced.", pattern: `(?i)\bPrivateKey[ \t]*=[ \t]*([A-Za-z0-9+/]{43}=)`, group: 1, ci: true, needs: []string{"privatekey"}, fold: true},
	{kind: "age-secret-key", desc: "age (and sops-age) secret key: AGE-SECRET-KEY-1 followed by 58 characters.", pattern: `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`, needs: []string{"AGE-SECRET-KEY-1"}},
	{kind: "pgp-private-key", desc: "A PGP private key block, BEGIN to END line.", pattern: `-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----`, needs: []string{"PGP PRIVATE KEY BLOCK"}},
	{kind: "putty-private-key", desc: "A PuTTY .ppk private section (Private-Lines: n and the base64 that follows).", pattern: `Private-Lines:[ \t]*\d+\r?\n(?:[A-Za-z0-9+/=]{20,}\r?\n?)+`, needs: []string{"Private-Lines:"}},
	{kind: "jwe", desc: "JSON Web Encryption token: five dot-separated base64url parts starting with eyJ.", pattern: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, needs: []string{"eyJ"}},
	{kind: "totp-seed", desc: "The secret= parameter of an otpauth:// (TOTP/HOTP) URI. Only the value is replaced.", pattern: `(?i)otpauth://[^\s"']*[?&]secret=([A-Za-z2-7=]{16,})`, group: 1, ci: true, needs: []string{"otpauth://"}, fold: true},
	{kind: "totp-migration-export", desc: "An otpauth-migration:// export, which holds every TOTP seed of an authenticator app.", pattern: `otpauth-migration://offline\?data=[A-Za-z0-9%+/=_-]+`, needs: []string{"otpauth-migration"}},
	{kind: "netrc-password", desc: "The password of a .netrc machine/login/password entry. Only the value is replaced.", pattern: `(?i)\bmachine[ \t]+\S+[ \t\r\n]+login[ \t]+\S+[ \t\r\n]+password[ \t]+(\S+)`, group: 1, ci: true, needs: []string{"machine"}, fold: true},
	{kind: "kubeconfig-credential", desc: "A token:, password: or client-key-data: line of a kubeconfig. Only the value is replaced.", pattern: `(?m)^[ \t-]*(?:token|client-key-data|password):[ \t]*["']?([A-Za-z0-9+/=._-]{16,})`, group: 1, needs: []string{"token:", "client-key-data:", "password:"}},
	// ---- headers and command-line arguments
	{kind: "http-auth-header", desc: "Value of api-key, x-api-token, x-access-token, private-token, x-vault-token, x-goog-api-key, proxy-authorization and similar headers. Only the value is replaced.", pattern: `(?im)(?:^|[^\w-])(?:api-key|apikey|x-api-token|x-access-token|x-secret|x-gitlab-token|private-token|x-vault-token|x-amz-security-token|x-goog-api-key|ocp-apim-subscription-key|proxy-authorization|x-auth-key|x-figma-token)["']?[ \t]*:[ \t]*["']?(?:Bearer[ \t]+|Basic[ \t]+|token[ \t]+)?([A-Za-z0-9._~+/=-]{8,})["']?`, group: 1, ci: true, needs: []string{"api-key", "apikey", "x-api-token", "x-access-token", "x-secret", "private-token", "vault-token", "gitlab-token", "figma-token", "security-token", "goog-api-key", "subscription-key", "proxy-authorization", "x-auth-key"}, fold: true},
	{kind: "cli-basic-auth-password", desc: "The password in curl -u user:password or --user user:password. Only the password is replaced.", pattern: `(?:^|[ \t])(?:-u|--user)(?:[ \t]+|=)["']?[^\s:'"]+:([^\s'"]{4,})`, group: 1, needs: []string{" -u", "--user"}},
	{kind: "cli-secret-argument", desc: "The value of --password, --token, --api-key, --secret and similar command-line flags. Only the value is replaced.", pattern: `(?i)--(?:password|passwd|token|api-?key|secret|auth-?token|access-?token|client-?secret|authkey|auth-key)(?:=|[ \t]+)["']?([^\s"']{6,})`, group: 1, ci: true, needs: []string{"--"}},
	{kind: "private-key-pem-truncated", desc: "A private-key BEGIN line followed by key material with no END line (output cut short). The BEGIN line and the base64 lines that follow are replaced; prose after them is left alone.", pattern: `-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[ \t]*\r?\n(?:(?:[A-Za-z0-9+/=]{16,}|[A-Za-z-]+: [^\n]*)[ \t]*\r?\n?)+`, needs: []string{"PRIVATE KEY"}, multiline: true},
	{kind: "json-secret-field", desc: `A JSON field named like a secret ("password", "secret_key", "client_secret", "api_key", "access_token", "private_key"...) with a string value of 8+ characters. Only the value is replaced. Covers Terraform state and docker inspect output.`, pattern: `(?i)"(?:password|passwd|secret|secret_key|secret_access_key|client_secret|api_key|apikey|access_token|refresh_token|auth_token|private_key|token)"[ \t]*:[ \t]*"([^"\s]{8,})"`, group: 1, ci: true, needs: []string{`"`}},
}

// offsetCands: a match starts back bytes before each occurrence of lit.
func offsetCands(lit string, back int) func(string) ([]int, bool) {
	return func(s string) ([]int, bool) {
		var xs []int
		for off := 0; ; {
			i := strings.Index(s[off:], lit)
			if i < 0 {
				break
			}
			if d := off + i; d-back >= 0 {
				xs = append(xs, d-back)
			}
			off += i + 1
		}
		return xs, true
	}
}

func hasAny(s string, needs []string) bool {
	for _, n := range needs {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// isPlaceholder reports values that are obviously not real secrets.
func isPlaceholder(v string) bool {
	if v == "" {
		return false
	}
	switch v[0] {
	case '<', '$', '{', '%', '*':
		return true
	}
	l := strings.ToLower(v)
	for _, w := range []string{"changeme", "placeholder", "your_", "your-", "xxxx", "....", "redacted", "example", "<", "${", "{{"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

var extraPats, extraPatsB []*secretPat

// genericExtras are shape-or-label detectors with no distinctive prefix: they run
// after the original detectors so a prefixed token keeps its own type.
var genericExtras = map[string]bool{"kubeconfig-credential": true, "json-secret-field": true, "cli-basic-auth-password": true,
	"cli-secret-argument": true, "http-auth-header": true, "npm-auth": true, "docker-registry-auth": true, "llm-provider-key": true,
	"cloudflare-api-key": true, "hetzner-api-token": true, "netrc-password": true, "private-key-pem-truncated": true}

func buildExtras() {
	W, WI := wordStart(false), wordStart(true)
	for _, e := range extras {
		e := e
		pre := W
		if e.ci || e.group > 0 {
			pre = WI
		}
		switch e.kind {
		case "azure-sas-token", "slack-webhook-url", "discord-webhook-url", "docker-registry-auth", "kubeconfig-credential", "cli-basic-auth-password",
			"cli-secret-argument", "json-secret-field", "netrc-password", "totp-seed", "npm-auth", "aws-session-token", "gcp-service-account-key-id",
			"headscale-preauth-key", "wireguard-private-key", "cloudflare-api-key", "hetzner-api-token", "llm-provider-key", "http-auth-header",
			"azure-storage-account-key", "putty-private-key", "totp-migration-export", "pgp-private-key":
			pre = nil
		}
		p := &secretPat{kind: e.kind, src: ws(e.pattern), group: e.group, pre: pre, tailed: e.tailed, needs: e.needs, fold: e.fold}
		switch e.kind {
		case "pgp-private-key", "putty-private-key", "netrc-password", "private-key-pem-truncated":
			p.multiline = true
		}
		if e.group > 0 {
			p.reject = isPlaceholder
		}
		switch e.kind {
		case "discord-bot-token":
			p.needs = nil
			p.cands = func(s string) ([]int, bool) {
				var xs []int
				for off := 0; ; {
					i := strings.IndexByte(s[off:], '.')
					if i < 0 {
						break
					}
					d := off + i
					for k := 24; k <= 26; k++ {
						if d-k >= 0 {
							xs = append(xs, d-k)
						}
					}
					off = d + 1
				}
				return sortedUnique(xs), true
			}
		case "mailchimp-api-key":
			p.needs = nil
			p.cands = offsetCands("-us", 32)
		case "terraform-cloud-token":
			p.needs = nil
			p.cands = offsetCands(".atlasv1.", 14)
		}
		if genericExtras[e.kind] {
			extraPatsB = append(extraPatsB, p)
		} else {
			extraPats = append(extraPats, p)
		}
	}
}

// ExtraTypes lists the extra detector names with their descriptions.
func extraDescriptions() map[string]string {
	m := map[string]string{}
	for _, e := range extras {
		m[e.kind] = e.desc
	}
	m["env-high-entropy"] = "NAME=value in an env-file shape (upper-case name, 32+ character value) where the value has high entropy and mixes letters and digits, and the name does not say hash, commit, version, id, url or similar. Conservative on purpose."
	m["env-secret-short"] = "NAME=value in an env-file shape where NAME says password, secret, token, api key, credential or passphrase and the value is 6 or more characters (shorter than the other detectors need). Names that end in _FILE, _PATH, _ID, _URL and similar, placeholders and booleans are skipped."
	m["cookie-secret"] = "Session-like values (names containing session, sid, token, auth, jwt, secret, key) in a Cookie: or Set-Cookie: header. Only the value is replaced."
	m["credit-card"] = "Payment card numbers (13 to 19 digits, valid Luhn checksum, known issuer prefix). Off by default; enable with AI_HOOKS_CARDS=1 or `redact --cards`."
	return m
}

// ---------------------------------------------------------------- custom passes

// EnableCards turns on the optional credit-card detector.
var EnableCards = false

var (
	reEnvLine      = regexp.MustCompile(`(?m)^([ \t]*(?:export[ \t]+)?)([A-Z][A-Z0-9_]{2,})=(["']?)([A-Za-z0-9+/_=.-]{32,})(["']?)[ \t]*$`)
	reEnvSkip      = regexp.MustCompile(`(?:SHA|HASH|COMMIT|DIGEST|CHECKSUM|REV|VERSION|BUILD|_ID$|_URL$|_URI$|_PATH$|_DIR$|_HOST$|_NAME$|_ENDPOINT$|UUID|ETAG|TRACE|SPAN|IMAGE|TAG$)`)
	reEnvShort     = regexp.MustCompile(`(?m)^([ \t]*(?:export[ \t]+)?)([A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)=(["']?)([^\s"'$<{]{6,})(["']?)[ \t]*$`)
	reEnvShortSkip = regexp.MustCompile(`(?:_FILE|_PATH|_DIR|_NAME|_ID|_URL|_URI|_HOST|_PORT|_LENGTH|_ENABLED|_TTL|_EXPIRY|_MINUTES|_SECONDS|_LABEL|_TYPE|_MODE|_ENV|_VERSION)$`)
	reCookie       = regexp.MustCompile(`(?im)^((?:set-)?cookie[ \t]*:[ \t]*)(.+)$`)
	rePair         = regexp.MustCompile(`([A-Za-z_][\w.-]*)=([A-Za-z0-9%._~+/=-]{16,})`)
	reCookieK      = regexp.MustCompile(`(?i)(session|sess|sid|token|auth|jwt|secret|key|csrf|remember)`)
	reCard         = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)
)

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := 0.0
	for _, c := range freq {
		n += c
	}
	h := 0.0
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func mixed(s string) bool {
	var d, l bool
	for _, r := range s {
		if unicode.IsDigit(r) {
			d = true
		} else if unicode.IsLetter(r) {
			l = true
		}
	}
	return d && l
}

func fpOf(v string) string { return fp(v) }

func customPasses(s string, counts map[string]int) string {
	if envLineCandidate(s) {
		s = reEnvLine.ReplaceAllStringFunc(s, func(m string) string {
			g := reEnvLine.FindStringSubmatch(m)
			name, val := g[2], g[4]
			if reEnvSkip.MatchString(name) || !mixed(val) || entropy(val) < 3.9 {
				return m
			}
			if counts != nil {
				counts["env-high-entropy"]++
			}
			return g[1] + name + "=" + g[3] + "<REDACTED:env-high-entropy:" + fpOf(val) + ">" + g[5]
		})
	}
	if strings.Contains(s, "=") && envLineCandidate(s) && reEnvShort.MatchString(s) {
		s = reEnvShort.ReplaceAllStringFunc(s, func(m string) string {
			g := reEnvShort.FindStringSubmatch(m)
			name, val := g[2], g[4]
			l := strings.ToLower(val)
			if reEnvShortSkip.MatchString(name) || isPlaceholder(val) || l == "true" || l == "false" || l == "yes" || l == "no" || l == "null" || l == "none" || strings.HasPrefix(val, "<REDACTED:") {
				return m
			}
			if counts != nil {
				counts["env-secret-short"]++
			}
			return g[1] + name + "=" + g[3] + "<REDACTED:env-secret-short:" + fpOf(val) + ">" + g[5]
		})
	}
	if strings.Contains(s, "ookie") || strings.Contains(s, "OOKIE") {
		s = reCookie.ReplaceAllStringFunc(s, func(m string) string {
			g := reCookie.FindStringSubmatch(m)
			out := rePair.ReplaceAllStringFunc(g[2], func(p string) string {
				kv := rePair.FindStringSubmatch(p)
				if !reCookieK.MatchString(kv[1]) {
					return p
				}
				if counts != nil {
					counts["cookie-secret"]++
				}
				return kv[1] + "=<REDACTED:cookie-secret:" + fpOf(kv[2]) + ">"
			})
			return g[1] + out
		})
	}
	if EnableCards {
		s = reCard.ReplaceAllStringFunc(s, func(m string) string {
			digits := strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, m)
			if !luhn(digits) || !cardPrefix(digits) {
				return m
			}
			if counts != nil {
				counts["credit-card"]++
			}
			return "<REDACTED:credit-card:" + fpOf(digits) + ">"
		})
	}
	return s
}

// envLineCandidate is a cheap test for "some line looks like NAME=value": an
// upper-case letter right after a line start (or indentation) and an '=' soon after.
func envLineCandidate(s string) bool {
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if strings.HasPrefix(s[j:], "export ") {
			j += len("export ")
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
		}
		if j < len(s) && s[j] >= 'A' && s[j] <= 'Z' {
			end := j + 80
			if end > len(s) {
				end = len(s)
			}
			if k := strings.IndexByte(s[j:end], '='); k > 0 && !strings.ContainsAny(s[j:j+k], " \t") {
				return true
			}
		}
		nl := strings.IndexByte(s[i:], '\n')
		if nl < 0 {
			return false
		}
		i += nl + 1
	}
	return false
}

func luhn(d string) bool {
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// cardPrefix accepts the major issuer ranges (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners).
func cardPrefix(d string) bool {
	p2 := d[:2]
	switch {
	case d[0] == '4':
		return len(d) == 13 || len(d) == 16 || len(d) == 19
	case p2 >= "51" && p2 <= "55", d[:4] >= "2221" && d[:4] <= "2720":
		return len(d) == 16
	case p2 == "34" || p2 == "37":
		return len(d) == 15
	case d[:4] == "6011" || p2 == "65":
		return len(d) >= 16
	case p2 == "35":
		return len(d) >= 16
	case p2 == "62":
		return len(d) >= 16
	case p2 == "36" || p2 == "38" || p2 == "30":
		return len(d) >= 14
	}
	return false
}
