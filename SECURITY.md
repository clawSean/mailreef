# Security Policy

Do not submit real email content, OAuth tokens, credential files, audit logs, or
personal addresses in issues or test fixtures. Use synthetic messages only.

Treat bypasses that expose email-derived prose to a tool-capable agent, allow a
caller-controlled executable/path, weaken fail-closed behavior, or broaden Gmail
scope as security vulnerabilities.

The injection gate is intentionally not a generic phishing or action-risk filter.
Human-facing calls to action remain summarizable inside the non-authorizing
envelope. Prompt injection means source content that targets an AI/assistant/
agent/model, its instructions or policy, its tools or secrets, or hidden/encoded
execution. The independent post-gate also blocks a summary that relays source
content as an instruction to the receiving agent. Human-facing OTP, MFA,
verification, password, and other credential content is not prompt injection by
itself and may pass only when evidence-backed; agent-directed attempts to obtain
or reveal secrets remain blocked. OTP/MFA/verification values are released only
from context-bound deterministic matches after both isolated gates pass. Mailreef
does not expose the arbitrary evidence quote used to validate a summary claim.

Full HTTPS links may pass only after both model gates as deterministic structured
untrusted data. A released code or link is evidence, not authorization to use it
or navigate; the calling workflow must already have user authorization for the
external action.

This project is experimental and disabled by default. A passing offline suite is
not proof that a live account or runtime has been safely configured.
