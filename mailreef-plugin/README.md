# Mailreef Plugin

OpenClaw plugin layer for Mailreef's prose-free Gmail discovery and screened
message reader.

It registers:

- owner-only tool `mailreef_read`
- authenticated command `/mailreef`
- dangerous node-host command `mailreef.broker`
- a validating node-invoke policy

The broker path, Python executable, node target, timeout, and account allowlist
are operator config. A caller may select only an explicitly allowlisted account;
the configured default is used when omitted. Successful broker output is transformed by two
native zero-tool completions on the active turn's explicitly allowlisted Luna
or Sol model, with strict deterministic validation between them. Raw source and
blocked candidates are not returned in tool details.

The detector targets agent-directed prompt injection and summary relay, not
ordinary requests to the human recipient. The isolated summarizer returns the meaning of a human
CTA; deterministic code adds the descriptive
`The email asks the reader to ...` frame after validation. `contentSignals`
uses neutral labels such as `human_action_requested`; the separate post-detector
receipt is the security verdict. Every envelope remains unable to authorize
action.

The tool contract documents all accepted fields. Use only `account`, `action`,
`messageId`, `max`, `days`, `after`, `before`, `from`, and `subjectContains` as
applicable. Raw Gmail `query`/`q` and legacy aliases such as `maxResults` or
`daysBack` are intentionally unsupported.

The broker uses deterministic local tripwires and has no Ollama or local-model
runtime dependency.

Defaults:

- account: `sean`
- allowed accounts: `sean` only until additional isolated OAuth grants are activated
- recent scope: 5 messages / 7 days
- historical discovery: 10 IDs/timestamps, inclusive dates through today,
  366-day window, 10-year age floor,
  sender/subject selector, inbox-only, no pagination
- command/CLI gate default: `openai/gpt-5.6-luna`
- ordinary agent turns: the exact active `openai/gpt-5.6-luna` or
  `openai/gpt-5.6-sol` model for both gates
- broker: `/Users/Sean/projects/mailreef/mailreef_broker.py`

Verification:

```bash
npm run check
```

This check does not activate the plugin or access Gmail. Follow the repository's
`docs/ACTIVATION.md` after explicit operator approval for deployment/runtime
changes.
