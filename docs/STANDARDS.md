# Standards and guidance this tool relates to

There is no ISO standard for "password format" that a tool can be compliant with. What exists is guidance on **how secrets must be handled** (stored, logged, transmitted, rotated) and on **how findings should be reported**. This page maps the controls that ai-hooks can help with. It is a mapping, not a certification: **using a tool does not make an organisation compliant with any standard.**

Legend: *Asks* = what the control requires, *Helps* = how ai-hooks contributes, *Does not cover* = what remains your job.

Confidence column: **verified** means the identifier and title were read from the primary source on 2026-11-13; **secondary** means confirmed from a reputable secondary listing only (the standard's text is paid or was not reachable); **unverified** means not confirmed, and no claim is made beyond the name.

## OWASP

| Source | Identifier | Asks | Helps | Does not cover | Confidence |
|---|---|---|---|---|---|
| [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | section on detection / logging | secrets must never be logged (mask or encrypt them); audit access to them | masks secret-shaped strings in command output before it reaches a log or transcript; reports what was masked by type | storing, rotating and issuing secrets (use a secrets manager) | verified |
| [ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md) | V16.2.5 | credentials and payment details are not logged; tokens only hashed or masked | the redactor and the PostToolUse hook keep credentials out of logs that capture agent output | application-side logging code | verified |
| [ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md) | V13.3.1 | secrets live in a secrets manager, not in source or build artifacts | `scan` finds secrets left in files, as SARIF for CI | enforcing that a manager is used | verified |
| [ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md) | V14.2.1, V14.2.6 | no sensitive data in URLs; mask sensitive data in output | detects passwords in URLs and masks values | classifying your data | verified |
| [ASVS 4.0.3](https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x15-V7-Error-Logging.md) | V7.1.1 | do not log credentials or payment details | as above | | verified |
| [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) | LLM02:2025 Sensitive Information Disclosure | sensitive data must not leak through model inputs and outputs | keeps secrets out of what an agent reads and therefore out of the model context and its provider's logs | what a model memorises from training data, or leaks it was never shown | verified |
| [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | LLM06:2025 Excessive Agency | limit what agents can do and see | one narrow guard on one class of command; `safe_run` can be disabled or allow-listed | granting an agent only the permissions it needs (sandboxing, least privilege) | verified |

## CWE

| Identifier | Title | Helps | Does not cover |
|---|---|---|---|
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | redacts secret-shaped values before they are logged by the agent harness | logging done by the applications themselves |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | stops secrets reaching the model provider and shared transcripts | exposure through other channels |
| [CWE-214](https://cwe.mitre.org/data/definitions/214.html) | Invocation of Process Using Visible Sensitive Information | the `background-secret` and `cli-secret-argument` checks flag secrets placed in argv, visible in `ps` | fixing the program that takes a secret as an argument |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) / [CWE-259](https://cwe.mitre.org/data/definitions/259.html) / [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | Hard-coded credentials / password / sensitive information in source | `scan` can find them in files and CI | removing and rotating them |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Cleartext storage; insufficiently protected credentials | detection only | storage design |

## NIST

| Source | Identifier | Asks | Helps | Does not cover | Confidence |
|---|---|---|---|---|---|
| [SP 800-53 Rev 5](https://github.com/usnistgov/oscal-content/blob/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json) | SI-15 Information Output Filtering | validate or filter information output | the redactor is an output filter for secret-shaped content | the rest of the control | verified |
| SP 800-53 Rev 5 | AU-3 Content of Audit Records | audit records must hold defined content | keeps credentials out of records that capture command output | what the records must contain | verified |
| SP 800-53 Rev 5 | IA-5(7) No Embedded Unencrypted Static Authenticators | no plaintext static authenticators in code or scripts | `scan` finds embedded credentials | replacing them | verified |
| SP 800-53 Rev 5 | AC-4 Information Flow Enforcement | control how information flows between systems | restricts one flow (secrets into an agent's context) | network-level flow control | verified |
| [SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) (Rev 4) | authenticator and lifecycle management | how verifiers store and handle authenticators | none directly: this guidance is about issuing and verifying authenticators, not detecting them in output | everything | verified (title and exact sections not confirmed) |

## ISO/IEC 27001:2022 Annex A (and 27002:2022)

The standard's text is paid; control numbers and titles below come from free listings (secondary). ai-hooks **supports** these controls; it does not satisfy them.

| Control | Title | Helps | Does not cover |
|---|---|---|---|
| 8.11 | Data masking | masks secret-shaped data in output | masking in applications and databases |
| 8.12 | Data leakage prevention | one control point against leakage of credentials to a model provider | endpoint and network DLP |
| 8.15 | Logging | keeps secrets out of logs that capture agent sessions | the log programme itself |
| 5.17 | Authentication information | helps keep authentication information out of places it should not be | allocation and management processes |

## PCI DSS v4.0.1, SOC 2

- **PCI DSS:** requirement 3.3.1 (sensitive authentication data is not retained after authorisation) and 3.4.1 (PAN masked when displayed) are the relevant ideas. The optional Luhn-checked card detector (`--cards`) can mask payment card numbers in agent output. Identifiers and wording are **secondary / unverified** here; this tool does not scope, assess or secure a cardholder data environment.
- **SOC 2** (AICPA Trust Services Criteria, 2017 with 2022 points of focus): CC6.1 (logical access), CC6.7 (restricting transmission and removal of information) and CC7.2 (monitoring for anomalies) are the nearest criteria, in general terms. Using ai-hooks may be one piece of evidence for an organisation's own controls; it is not an audit result.

## SARIF

`ai-hooks scan --format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log (schema `https://json.schemastore.org/sarif-2.1.0.json`) that GitHub code scanning and other CI tools can ingest: one `rule` per detector type used, one `result` per finding with `ruleId`, a `message`, a `physicalLocation` (file and line) and `partialFingerprints`. **No secret value is ever included**, only the detector, the location and the fingerprint. Upload it with `github/codeql-action/upload-sarif`.

## Machine-readable interfaces

- `ai-hooks scan --format json|sarif`, `ai-hooks redact --json`, `ai-hooks guard --json`, `ai-hooks test --json`
- `ai-hooks rules list --json` (guard rules, detectors, old-name aliases), `ai-hooks rules schema` (JSON Schema of the rules file), `ai-hooks rules validate FILE`
- Exit codes: `0` success, allowed, or nothing found; `1` findings (scan) or a failed self-test; `2` blocked by the guard, or bad usage.

## Not claimed

Compliance with any standard; an assessment of any control; coverage of any control outside the narrow behaviours listed above.
