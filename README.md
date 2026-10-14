# Commix-to-Burp Extension

**Command injection exploitation, powered by commix - without leaving Burp.**

A [Burp Suite](https://portswigger.net/burp) extension that drives [commix](https://github.com/commixproject/commix)
over its REST API ([`commixapi.py`](https://github.com/commixproject/commix/wiki/API)) - right-click
a request anywhere in Burp (Proxy history, Repeater, Target) and send it straight to a command
injection scan, with the log and the findings read back into a tab of their own.

Built against Burp's modern [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/),
not the legacy (and increasingly unmaintained) Jython extender API.

## What it does

- Right-click any request → **Scan**.
- A tabbed options dialog covers commix's own flags - Detection shown by default, Injection,
  Session & request and Post-exploitation behind **Show advanced options**. Conflicting pairs
  (`--oob` with a technique, Random vs Mobile User-Agent) disable each other instead of failing
  the scan.
- Sends the request over the API as-is - URL, method, body, cookies, headers.
- One tab per scan: live status, a colored log, a findings table. A colored dot on the tab shows
  health at a glance. **Edit options & scan again** re-runs without going back to Burp's history.
- Confirmed findings are also raised as Burp Scanner audit issues - severity, confidence, payload
  and remediation included.
- Host, port and token live under a **commix** settings tab, saved with the project and tested
  automatically on load.

## Requirements

- Burp Suite (Professional or Community), a recent enough release to support the Montoya API
  (2023.12 or later).
- A running `commixapi.py` server - start it from a commix checkout:
  ```bash
  python commixapi.py
  ```
  which prints the host, port and token to use.
- A JDK to *build* the extension - 17 at minimum, since that's what Montoya API 2023.12.1 is
  compiled against. The project's own Gradle toolchain targets 25 (the current LTS) and downloads
  it automatically if the machine doesn't have one; either way this is only a build-time dependency,
  not something Burp itself needs at runtime.
- The bundled Gradle wrapper (8.5) is a separate, older constraint: it can only run on Java 8
  through 21, whatever the toolchain above asks for. If every JDK on your machine is already 22 or
  newer - plausible on a machine set up with only "the current LTS" in mind - point `JAVA_HOME` at
  one from that 8-21 range (any of them, not necessarily 17) before running `./gradlew build`, or
  the wrapper itself won't start.

## Building

```bash
./gradlew build
```

> [!NOTE]
> The first build can take a minute longer than usual: Gradle downloads JDK 25 on its own if the
> machine doesn't already have one, to satisfy the toolchain in `build.gradle`. Later builds reuse it.

The extension jar is written to `build/libs/commix-to-burp-v1.0.0.jar` - a shadow ("fat") jar carrying its own
JSON library, with nothing else bundled (Burp supplies the Montoya API itself at runtime). It's the
only jar the build produces - Gradle's own `jar` task, which would otherwise leave a second, unusable
jar in the same folder, is disabled.

## Installing in Burp

1. **Extensions** → **Installed** → **Add**.
2. Extension type: **Java**.
3. Select `build/libs/commix-to-burp-v1.0.0.jar`.

<img alt="1" src="https://github.com/user-attachments/assets/702d1933-3fef-4211-8a13-c876871114f5" />

4. Open the new **commix** tab - it leads with what to do first - fill in the host/port/token
   `commixapi.py` printed on startup, and click **Save & test**.
<img alt="2" src="https://github.com/user-attachments/assets/a87dc48f-0002-41e4-b6a7-646e93070489" />

## Using it

1. Right-click any request in Proxy's history, in Repeater, in Target's site map and choose **Scan**.
<img alt="3" src="https://github.com/user-attachments/assets/28c87b46-33b1-4a2c-8a23-91bece839ee9" />

2. A tabbed options dialog opens first, covering detection, tamper scripts, injection, session and
   request settings, and post-exploitation - everything you'd otherwise set with command-line flags,
   pre-filled with whatever was chosen last time. **Start Scan** begins the scan; **Cancel** closes
   the dialog without doing anything.
<img alt="4" src="https://github.com/user-attachments/assets/ed077764-161e-479a-94bf-989b5da344ec" />

3. A new tab opens under **commix**, named after the target. It polls the scan's status and log on
   its own; the findings table fills in once something is confirmed.
<img alt="5" src="https://github.com/user-attachments/assets/eb45c404-742f-4407-a4c1-336b4029a2e9" />
  
   > [!NOTE]
   > **Stop** asks the scan to end and write down what it has; **Kill** ends the process outright,
   > without a report; **Edit options & scan again** reopens the options dialog and starts a fresh
   > scan against the same request - useful after a failed or unwanted run, without going back to
   > Burp's history to right-click again.

   
5. Confirmed findings also raised as Burp Scanner issues.
<img alt="6" src="https://github.com/user-attachments/assets/17d83002-4d76-4070-b915-613c196f59a8" />

> [!NOTE]
> commixapi.py traffic goes through Burp's own networking - an upstream proxy or broad
> session-handling rules apply to it too, same as any other request Burp sends.

## What this is not, yet

- No bulk/crawl-mode support (the API itself does, over a bulk file, a proxy log, a sitemap or a
  crawl - the extension only drives it one request at a time so far).

> [!IMPORTANT]
> This is the official commix-to-burp extension. 
> Not on the BApp Store yet - but it's coming; submission is in progress, tracked on [PortSwigger/extension-portal](https://github.com/PortSwigger/extension-portal/issues).

## Changelog

See [doc/CHANGELOG.md](doc/CHANGELOG.md).

## License

[Apache License 2.0](doc/LICENSE).
