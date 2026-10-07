# How I found a path-access bypass in an MCP server — my first security disclosure

*A write-up of my first real vulnerability finding: a bypass of a documented
file-access control in ImageSorcery MCP, found by reading the source, not by
running a scanner.*

---

## Background: why MCP servers are a good place to start

I'm a second-year computer science student learning application security. I'd
done CTFs, PortSwigger labs, and my first bug bounty recon, but I wanted to find
something real in a real codebase.

The Model Context Protocol (MCP) turned out to be a good place to look. MCP is
how AI assistants connect to external tools — file systems, APIs, databases. It's
new, it's spreading fast, and because the trust model assumes tool calls are
benign, a lot of servers ship with the classic vulnerabilities: command
injection, path traversal, SSRF. Research through 2025 and 2026 found shell
injection in a large share of popular MCP servers, and path traversal in most of
the ones that touch files.

The reason these are findable by a beginner: the bug classes are old and well
understood, and the code is young. You don't need novel techniques — you need to
read carefully.

## The method: source-to-sink

I used one algorithm the whole way through. Strip away the tooling and security
code review is a single move, repeated:

> Find a dangerous **sink** → walk backwards to where the data came from (the
> **source**) → check whether a real **sanitizer** sits in between.

If attacker-controlled data reaches a sink with no sanitizer, you have a finding.
Reading backwards is faster than reading top to bottom, because there are far
fewer dangerous sinks than there are inputs.

The dangerous sinks I care about:

- `subprocess` / `os.system` → command injection
- `open()` / `Path()` → path traversal
- `requests.get()` / `httpx` → SSRF
- `eval` / `exec` / `pickle.loads` → code execution

And in MCP specifically, the **source** is almost always a `@tool` function's
parameter — because the thing calling the tool is an LLM, which can be
prompt-injected. In MCP, the AI agent itself is the attack vector.

## Choosing a target

I skipped the flagship servers. The official reference servers and the big
third-party ones have been audited hard. Instead I looked for smaller servers
where a dangerous operation is a *sub-feature* rather than the point of the tool.

ImageSorcery MCP fit: an image-processing server (blur, crop, detect, OCR) with
around 330 stars. Most of its tools are image operations, but a few of them load
a machine-learning model by name — and that's where filesystem access crept in.

## The first thing that caught my eye

Running a grep for path sinks surfaced a file called `path_access.py`. Its very
name said "someone thought about file access here," which makes it the most
interesting file in the repo. It implements a documented control:

```
IMAGESORCERY_AVAILABLE_PATHS=/home/user/images
```

When that environment variable is set, the operator wants to confine the server
to specific directories. The middleware enforces it by inspecting tool arguments:

```python
def is_path_argument(name: str) -> bool:
    return name == "path" or name.endswith("_path")
```

Read that carefully. The control only inspects arguments whose name is **exactly
`path`** or **ends with `_path`**. Anything else — `filename`, `directory`,
`source`, `model_name` — is never checked.

That's the kind of line that makes you stop, because the control's *purpose*
("confine file access") and its *mechanism* ("check names that look like paths")
are not the same thing. If any parameter reaches the filesystem under a
different name, the confinement quietly fails.

## The gap

So I went looking for a parameter that reaches a filesystem path but isn't named
`path` or `*_path`. I found it in `detect.py` and `find.py`:

```python
def get_model_path(model_name):
    model_path = Path("models") / model_name   # no validation
    if model_path.exists():
        return str(model_path)
    return None
```

`model_name` is a tool parameter on the `detect` and `find` tools. It's passed
straight into `Path("models") / model_name`. And `model_name` is neither `path`
nor `*_path`, so the middleware never inspects it.

That means the value flows: **tool parameter → filesystem path → file load**,
with the sanitizer that was supposed to guard that boundary stepping right past it.

## Proving it, not assuming it

A grep hit is a lead, not a finding. Before I claimed anything, I ran the actual
source code — not a paraphrase of it — to confirm the behaviour. I loaded the
real `path_access.py`, stubbed only the unrelated framework imports, and tested:

```
is_path_argument('path')       = True
is_path_argument('input_path') = True
is_path_argument('model_name') = False      <-- not inspected

# a tool call carrying both a checked and an unchecked path-like argument
args supplied        : ['input_path', 'model_name']
args control inspects: ['input_path']       <-- model_name is invisible to it

Path('models') / '../../../../etc/passwd' -> resolves to /etc/passwd   (exists=True)
Path('models') / '/etc/hosts'             -> /etc/hosts                (exists=True)
```

That's the whole thing, demonstrated. The middleware checks `input_path` and
ignores `model_name`; `model_name` then resolves cleanly out of the allowed
directory via `../` traversal or an absolute path.

## Impact — stated honestly

This is a **security-control bypass**: the operator's configured file-access
confinement (`IMAGESORCERY_AVAILABLE_PATHS`) does not hold, because a parameter
reaches the filesystem outside the name-based check.

The sharper edge: the resolved path is handed to Ultralytics to load a `.pt`
model, and `.pt` files are loaded through `torch.load`, which is pickle
deserialization. If a malicious model file exists at an attacker-reachable path,
that becomes code execution. But that last step needs a file to be present, so I
described it as *conditional* — the certain, defensible claim is the bypass
itself.

Understating a finding costs you nothing. Overstating one gets the whole report
dismissed.

## The report

I wrote it up as: summary, affected code, reproduction steps, executed evidence,
impact, and a suggested fix (validate the resolved path inside `get_model_path`,
and/or cover `model_name` in the middleware). Then I filed it as a public GitHub
issue, since the project has no `SECURITY.md` and no private reporting channel:

`github.com/sunriseapps/imagesorcery-mcp/issues/18`

## What I actually learned

- **A dangerous sink is not a vulnerability.** The chain is source → path → sink
  → reachable → attacker-controlled → impact. Most leads die at the reachability
  step, and killing them there is what makes your real reports credible.
- **"By design" is the first question, not the last.** Half the servers I looked
  at were shell runners — running commands was the feature, so there was nothing
  to report. The finding only exists where a tool claims a restriction it doesn't
  fully enforce.
- **Read the control, not just the sink.** The most interesting code is the code
  that tries to be secure. A name-based check, a comment, a guard in one function
  but not its sibling — that's where bugs hide.
- **Prove it by running it.** Loading the real source and printing the real
  output turned "I think" into "here is the evidence."
- **Method beats tooling.** No scanner found this. A grep for sinks, careful
  reading, and a backward trace did.

It took a few dozen servers' worth of false starts to find one real bug. That's
the actual ratio in this work — and now I know exactly how to do the next one.
