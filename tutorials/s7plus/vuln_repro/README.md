# S7-1200 CPU 1214C PoC Candidate Notes

Target model:

```text
SIMATIC S7-1200 CPU 1214C DC/DC/DC
Order number: 6ES7214-1AG40-0XB0
Lab target: 192.168.0.13
```

The previous CVE-2025-24812 and SSA-625789 reproduction material was removed.
This directory now tracks PoC candidates that are more likely to be actionable
for this specific model.

## Downloaded PoC Sources

```text
poc_sources/exploitdb/exploitdb_19833_s7_1200_start_stop_msf.rb
  Exploit-DB 19833, Metasploit auxiliary module for S7-1200 CPU START/STOP.

poc_sources/exploitdb/exploitdb_38964_s7_1200_cpu_command_msf.rb
  Exploit-DB 38964, updated S7-1200 CPU command module, tested by author on S7-1214C.

poc_sources/exploitdb/exploitdb_44667_s7_1200_csrf.html
  Exploit-DB 44667, web CSRF PoC for older S7-1200 firmware before V4.1.3.

poc_sources/harpos7/HarpoS7/
  HarpoS7 GitHub repository, S7CommPlus authentication/legitimation PoC library.
```

## Environment

Configured locally without sudo:

```text
.NET SDK: 8.0.422
DOTNET_ROOT: ~/.dotnet
```

Load environment:

```bash
source tutorials/s7plus/vuln_repro/env.sh
```

Build HarpoS7:

```bash
tutorials/s7plus/vuln_repro/build_harpos7.sh
```

Run HarpoS7 PoC without an access password:

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
tutorials/s7plus/vuln_repro/run_harpos7_poc.sh
```

Run HarpoS7 PoC with an access password:

```bash
S7_TARGET=192.168.0.13 S7_PORT=102 \
S7_ACCESS_PASSWORD='your-password' \
tutorials/s7plus/vuln_repro/run_harpos7_poc.sh
```

Current test result:

```text
HarpoS7 builds successfully.
The PoC connects to 192.168.0.13:102, creates a session object, reads the
session id, fingerprint, and challenge, and finds the matching public key.
The PLC closes the connection after the set-multi-vars authentication request.
Post-test S7 health check remains healthy.
```

## Candidate Ranking

### 1. HarpoS7 / S7CommPlus Legitimation

Source:

```text
https://github.com/bonk-dev/HarpoS7
```

Why it is relevant:

```text
The project explicitly lists S7-1200 1214C DC/DC/DC, 6ES7214-1AG40-0XB0,
as a tested device. It supports S7CommPlus legacy challenge authentication,
TLS authentication, and password legitimation workflows.
```

Expected value:

```text
Best match for modern S7-1200 V4/TIA traffic.
Useful for building authenticated S7CommPlus sessions and generating deeper
protocol states for fuzzing.
```

Limitations:

```text
Requires .NET 8 SDK.
It is a PoC library, not a one-command vulnerability exploit.
Password legitimation still requires a password and correct challenge/session
context.
```

Next step:

```bash
dotnet build tutorials/s7plus/vuln_repro/poc_sources/harpos7/HarpoS7/HarpoS7.sln
```

Then inspect and adapt:

```text
poc_sources/harpos7/HarpoS7/HarpoS7.PoC/
```

### 2. CVE-2024-47100 / SSA-717113 Web CSRF

Source:

```text
https://cert-portal.siemens.com/productcert/html/ssa-717113.html
```

Why it is relevant:

```text
The official affected list includes CPU 1214C DC/DC/DC 6ES7214-1AG40-0XB0.
Affected versions are before V4.7.
```

Expected value:

```text
Relevant if the PLC web interface is enabled and firmware is below V4.7.
The impact is CPU mode change through CSRF when a legitimate authenticated
user with sufficient permissions clicks a malicious link.
```

Limitations:

```text
Needs an authenticated browser session.
Not a direct unauthenticated TCP/102 exploit.
No specific public full PoC was found beyond advisory-level description.
```

Next step:

```text
Check whether HTTP/HTTPS web server is enabled and identify firmware version.
If vulnerable, build a local HTML CSRF form based on observed web requests
from the real PLC UI.
```

### 3. Exploit-DB 38964 S7-1200 CPU Command Module

Source:

```text
https://www.exploit-db.com/exploits/38964
```

Why it is relevant:

```text
The module says it was tested on Siemens Simatic S7-1214C.
It sends S7CommPlus-like CPU command packets over TCP/102.
```

Expected value:

```text
Potentially useful as a packet corpus and historical START/STOP reference.
```

Limitations:

```text
No CVE.
Metasploit module is old.
Likely targets old firmware/session behavior and may fail on modern V4.x CPUs.
Requires Metasploit.
Can change CPU state.
```

Next step:

```text
Install Metasploit only if we decide to test this path.
Before active use, extract packet sequences and replay conservatively with
health checks, instead of immediately cycling CPU mode.
```

### 4. Exploit-DB 19833 S7-1200 START/STOP Module

Source:

```text
https://www.exploit-db.com/exploits/19833
```

Why it is relevant:

```text
Historical public S7-1200 START/STOP PoC.
```

Limitations:

```text
No CVE.
Published in 2012.
Very likely applicable only to old firmware behavior.
Can change CPU state.
```

### 5. CVE-2015-5698 / Exploit-DB 44667 Web CSRF

Source:

```text
https://www.exploit-db.com/exploits/44667
https://nvd.nist.gov/vuln/detail/CVE-2015-5698
```

Why it is less preferred:

```text
The public PoC is a simple HTML form posting to /CPUCommands.
It targets firmware before V4.1.3.
If the PLC firmware is newer, this is likely not applicable.
```

Usefulness:

```text
Good historical reference for web CSRF testing.
Less relevant than CVE-2024-47100 for V4-series CPUs before V4.7.
```

## Immediate Recommendation

The most realistic next path is:

```text
1. Identify firmware version and whether the web server is enabled.
2. Try HarpoS7 as the modern S7CommPlus path.
3. If firmware < V4.7 and web server is enabled, test CVE-2024-47100-style CSRF
   by capturing real CPU mode-change web requests and building a local CSRF page.
4. Treat Exploit-DB 19833/38964 as historical packet references first, not as
   safe one-click exploits.
```

## Sources Checked

```text
Siemens SSA-717113: CVE-2024-47100, S7-1200 web CSRF before V4.7
Siemens SSA-232418: CVE-2019-10943/CVE-2019-10929
NVD CVE-2015-5698: S7-1200 web CSRF before V4.1.3
Exploit-DB 19833, 38964, 44667
HarpoS7 GitHub repository
```
