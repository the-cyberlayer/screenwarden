# ScreenWarden

Open-source security layer for AI agents that operate Android phones. By The CyberLayer.

## The problem

Phone-using agents read the screen and act on it: they tap, type and send SMS. Research published
in July 2026 showed that open-source Android agents (AppAgent, Mobile-Agent-v3, Open-AutoGLM,
MobA and others) can be hijacked by content the human never sees, such as invisible text, overlays
and spoofed screens, and by malicious SMS. Confirmation prompts alone are not enough.

## How it works

ScreenWarden sits between the agent and the phone, with two checkpoints.

```
UI dump + screenshot -> sanitize_screen() -> LLM -> check_action() -> adb
                              |                           |
                              +----- JSONL decision log --+
```

- **`sanitize_screen(ui_tree, context)`** removes what a human cannot see or should not be obeyed:
  zero-size, off-screen and tiny text, text the tree reports but the screenshot does not show,
  instruction-like text from SMS and web pages, and windows from other packages. It also flags
  login pages on untrusted hosts and payment screens, and records OTPs seen on screen.
- **`check_action(action, context)`** returns `ALLOW`, `BLOCK` or `ASK_HUMAN` with a reason and an
  OWASP tag. It blocks OTP forwarding, unknown recipients, credential entry, payments, installs and
  settings changes. Its core check is data flow: a recipient, URL or message taken from untrusted
  content and absent from the user's goal is blocked, however the model was persuaded.
- **`policy.yaml`** holds every pattern, package list, verdict and reason.
- **The decision log** records each decision as JSONL, with digit runs masked so codes are not stored.

```python
from screenwarden import Guard

guard = Guard("Read my messages and summarise them")
screen = guard.observe(ui_xml, foreground_package, screenshot_png)  # screen.text goes to the LLM
decision = guard.check({"type": "send_sms", "recipient": "+447700900666", "text": "482913"})
print(decision.verdict, decision.owasp, decision.reason)
```

`Guard` wraps the two functions and keeps taint across screens, so a code seen on one screen is
still protected on the next.

## Quick start

Requires Python 3.11+, adb and an Android emulator. On WSL, the Windows `adb.exe` works.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[agent,dev]"
pytest
```

The reference agent is configured through environment variables:

| Provider | Settings |
|---|---|
| Anthropic (default) | `ANTHROPIC_API_KEY`, optional `ANTHROPIC_MODEL` |
| Ollama | `LLM_PROVIDER=ollama`, optional `OLLAMA_MODEL`, `OLLAMA_HOST` |

```bash
python -m reference_agent --goal "Read my latest SMS messages" --guard on
```

## Demo

Start an emulator, and open Chrome once to clear its first-run screens. Then:

```bash
./demo.sh all              # sms | web | login | all
./demo.sh all --scripted   # no model: replays a fixed plan
```

Each attack runs with the guard off, then on. Afterwards the script reads the phone's sent-SMS
store, so the result is what actually left the device.

| Attack | What the agent is exposed to | Guard on |
|---|---|---|
| Malicious SMS | OTP, then a fake bank asking to forward it | `otp_exfiltration`, ASI02 |
| Hidden web instruction | `opacity:0` text asking for an SMS to the attacker | `invisible_text`, then `tainted_origin`, ASI01 |
| Spoofed login | Bank-styled login page on an untrusted host | `spoofed_screen`, ASI01 |

`--scripted` proves the adb and guard path on a real emulator. It shows what a hijacked model would
do, not that a model was hijacked. Whether a given model obeys an attack with the guard off depends
on the model.

### Which web hiding techniques reach the agent

Tested on Chrome for Android, Android 15 (`attacks/web/probe.html`):

| Result in the UI tree | Technique | Detected by |
|---|---|---|
| Absent | `display:none`, `visibility:hidden`, `aria-hidden` | Not needed |
| Bad geometry | `font-size:1px`, off-screen, sr-only clip, 1px `aria-label` | Geometry |
| Normal bounds | `opacity:0`, same colour as background, `transparent`, `clip-path`, `height:0`, covered by another element | Screenshot contrast |
| Bounds of a larger area | `font-size:0`, `transform:scale(0)` | Instruction patterns and data flow only |

## OWASP Agentic Top 10 mapping

| Risk | ScreenWarden controls |
|---|---|
| ASI01 Agent Goal Hijack | Hidden text removal, untrusted instruction removal, overlay and spoofed page detection, data-flow check on action parameters |
| ASI02 Tool Misuse | OTP, credential, payment, install and settings rules, unknown recipient rule, default `ASK_HUMAN` for unknown actions |

## Limitations

- **Patterns can be reworded.** Instruction detection is regular expressions, in English only.
  Data-flow rules and the pixel check exist because of this, but neither is complete.
- **Data flow is heuristic.** A model can paraphrase content, or a number can be reformatted, so
  taint is lost. An instruction with no action parameters, such as "tell the user to call the bank",
  passes through.
- **The pixel check needs a screenshot and Pillow.** Without them it is skipped. It only inspects
  outside-world text. It misses text drawn over busy backgrounds, and `font-size:0` and `scale(0)`
  text whose box covers other content. Blank captures disable it.
- **Visible attacks stay visible.** A message that reads as a plain request and contains no action
  parameters may reach the model as data.
- **Reference apps only.** Package lists, button patterns and fixtures come from Google Messages and
  Chrome on one Android 15 emulator image. Other apps need policy entries.
- **Overlay detection is not proven end to end.** It uses `uiautomator dump --windows`, and is tested
  on a real multi-window dump with a foreign window added, not with a real overlay app.
- **Spoof detection is host-based.** It relies on the browser URL bar and an allowlist, so it does
  not cover phishing inside apps.
- **This is a library the agent chooses to call.** It is not enforced by the OS, so a compromised
  host process can skip it.

## Roadmap

- Instruction detection beyond English, with an optional local classifier
- Provenance tracking through model output
- Real overlay test app and non-Google messaging apps
- Adapters for open-source phone agents
- Enforcement below the agent, such as an adb proxy

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 The CyberLayer (Aegean Ventures Global Ltd).
