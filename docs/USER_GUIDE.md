# ScreenWarden user guide

For teams that run an AI agent on Android phones.

## What you install, and where

| Where | What |
|---|---|
| The computer or server that runs your agent | ScreenWarden, Python 3.11+, `adb` |
| The phone | Nothing |

ScreenWarden runs next to your agent, not on the phone. It works with agents that control the phone
over adb. Agents that run inside the phone, or that use Appium, are not supported yet.

ScreenWarden is not on PyPI yet, so install it from the repository:

```bash
git clone <repository-url> screenwarden
cd screenwarden
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[pixels]"
```

`pixels` adds Pillow, which enables the screenshot check for invisible text. Without it, that check
is skipped.

## Choose an integration

| | SDK | adb proxy (experimental) |
|---|---|---|
| Change to your agent | About two calls | None, one environment variable |
| Cleans the screen the model sees | Yes | No |
| Stops dangerous actions | Yes | Yes |
| Language | Python | Any agent that uses the `adb` client |
| An agent can skip it | Yes, by not calling it | Yes, if it can reach the real adb server |

Use the SDK if your agent is in Python. Use the proxy if you cannot change the agent.

## Option 1: SDK

Create one `Guard` per task, and give it the user's own goal. Then make two calls in your loop.

```python
from screenwarden import Guard

guard = Guard("Read my messages and summarise them", log_path="decisions.jsonl")

while not finished:
    # 1. Before the model sees the screen
    screen = guard.observe(ui_xml, foreground_package, screenshot_png)
    action = your_model(goal, screen.text)      # send screen.text, not the raw XML

    # 2. Before the phone acts
    decision = guard.check(action)
    if decision.allowed:
        run_on_phone(action)
    elif decision.verdict.value == "ASK_HUMAN" and user_approves(decision.reason):
        run_on_phone(action)
    else:
        tell_the_model_it_was_refused(decision.reason)
```

`ui_xml` is the output of `uiautomator dump`. The package and screenshot are optional but recommended.
Target elements with the ids from `screen.elements`, whose `center` gives you tap coordinates.

### Action format

Convert your agent's actions to these dictionaries before calling `guard.check`.

| Action | Dictionary |
|---|---|
| Tap | `{"type": "tap", "target": 3}` |
| Type | `{"type": "type", "target": 3, "text": "..."}` |
| Send an SMS | `{"type": "send_sms", "recipient": "+44...", "text": "..."}` |
| Open a URL | `{"type": "open_url", "url": "..."}` |
| Open an app | `{"type": "open_app", "package": "com.android.chrome"}` |
| Install | `{"type": "install", "package": "..."}` |
| Other key press | `{"type": "key"}` |
| No risk | `{"type": "back"}`, `home`, `scroll`, `swipe`, `wait`, `done`, `read` |

Any other type returns `ASK_HUMAN`.

### Several agents on one phone

Give all agents one session. Taint is then shared, and each agent is judged against the user's goal,
not against tasks that agents hand each other.

```python
from screenwarden.session import SharedSession

session = SharedSession("Summarise my inbox", log_path="decisions.jsonl")
reader = session.guard(model="llama3.2:3b")
sender = session.guard(model="qwen2.5:3b")
```

## Option 2: adb proxy (experimental)

The proxy has only been tested against a simulated adb server, not a real phone.

Start the proxy with the user's goal, then point your agent at it:

```bash
python -m screenwarden.adb_proxy --goal "Read my messages" --log decisions.jsonl
ANDROID_ADB_SERVER_PORT=5038 python your_agent.py
```

- All agents behind one proxy share one session.
- Commands that only read pass through. Refused commands return an adb error starting with `ScreenWarden`.
- There is no human to ask, so `ASK_HUMAN` is refused.
- Commands it cannot classify, chained shell commands and file pushes are refused.
- It learns the screen from the UI dumps your agent reads. An agent that only uses screenshots gets no
  data-flow protection.
- For real enforcement, stop the agent from reaching the real adb server, for example by running it
  in a separate container or network namespace.

## Reading decisions

| Verdict | Meaning | What your agent should do |
|---|---|---|
| `ALLOW` | No rule matched | Run the action |
| `ASK_HUMAN` | A person must decide | Ask, and refuse if nobody answers |
| `BLOCK` | Not allowed | Do not run it |

Each decision also has `reason`, `owasp` and `rule`. Every decision is added to a JSONL log, with digit
runs masked so that codes and phone numbers are not stored:

```json
{"ts": "2026-11-02T20:47:53.120+00:00", "event": "check_action", "verdict": "BLOCK",
 "rule": "otp_exfiltration", "owasp": "ASI02", "reason": "Verification code would leave the device in a message"}
```

## What is blocked by default

| Rule | Default | Softer when the goal mentions it |
|---|---|---|
| Codes sent out of the device, parameters taken from screen content | `BLOCK` | No |
| Recipients not named in the goal, credential entry, spoofed login pages | `BLOCK` | No |
| Payments, app installs, settings changes | `BLOCK` | `ASK_HUMAN` |
| Payment screens, overlays, codes typed into apps, unknown actions | `ASK_HUMAN` | No |

## Configuration

You should not need app-specific rules for the checks above that follow data, but the defaults were
built on Google Messages and Chrome. To change anything, copy `screenwarden/policy.yaml`, edit the copy
and point to it:

```bash
export SCREENWARDEN_POLICY=/path/to/policy.yaml
```

| To | Edit |
|---|---|
| Allow a contact | `known_contacts`, or `Guard(..., known_contacts=[...])` |
| Treat another app's text as untrusted | `packages.messaging` or `packages.browsers` |
| Trust another login site | `trusted_login_domains` |
| Change or disable a rule | `rules.<name>.verdict`, or `enabled: false` |

Text from apps that are not on these lists is treated as trusted today, except inside a WebView. Add
the apps your agent reads external content from.

## Try it first

```bash
pip install -e ".[agent,dev]"
pytest
./demo.sh all --scripted
```

The demo needs a running emulator, and Chrome opened once to clear its first-run screens. `--scripted`
uses no model. To use a local model, run Ollama, then set `LLM_PROVIDER=ollama` and `OLLAMA_MODEL`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Normal messages are blocked | The recipient is not in the goal. Name it there or add a known contact |
| `unsafe_screen` on every step | The UI dump failed or is empty, so check `adb` and the dump output |
| Invisible text gets through | Pass a screenshot and install the `pixels` extra |
| Too many `overlay_present` prompts | Add the app to `packages.overlay_allowed` |
| Nothing is logged | Check `log_path`, or set `SCREENWARDEN_LOG` |

## Limits

ScreenWarden reduces the risk that a hijacked agent harms the user. It does not guarantee it. It does
not check what the agent tells the user, instruction patterns are English only, and it can be skipped
by a host that does not call it. See [Limitations](../README.md#limitations).
