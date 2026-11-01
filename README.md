# plex2shell

Security research project documenting and validating an unauthenticated remote
code execution issue affecting Plex Media Server. The issue is addressed in
Plex Media Server **1.43.3.10861**.

> **Defensive guidance:** Upgrade Plex Media Server promptly. This repository
> contains proof-of-concept code capable of executing commands on a target
> system. Do not run it against systems unless you own them or have explicit
> authorization.

## Vulnerability overview

The issue affects Plex Media Server versions up to **1.43.3.10828** and can
allow a remote, unauthenticated party to reach code execution through a chain
of server-side request and file-handling flaws.

| Field | Details |
| --- | --- |
| Affected software | Plex Media Server |
| Affected versions | Up to 1.43.3.10828 |
| Fixed version | 1.43.3.10861 |
| CVSS 3.1 | 9.8 (Critical) |
| Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Impact | Potential unauthorized command execution and compromise of the Plex host |

## Related CVEs

| CVE | Primitive |
| --- | --- |
| CVE-2026-96652 | Unauthenticated SSRF via `/player/timeline` `protocol=` |
| CVE-2026-96654 | Loopback pivot: dead auth guard + `searchOne` `identifier=` injection |
| CVE-2026-96655 | Owner-authed transcoder SSRF + arbitrary-path file write (`dump-yuv`) |
| CVE-2026-96656 | Code execution via unsigned codec `dlopen` in the Codecs set-dir |

See the [technical write-up](https://zmain.info/blog/plex2shell) for the
research context and attribution.

## Impact

Successful exploitation could compromise the Plex server under the privileges
of its service account, exposing data accessible to that account and affecting
the availability and integrity of the host. The consequences depend on the
server's permissions, network placement, and stored credentials.

## Features

- Proof-of-concept research implementation for the vulnerability chain
- Linux and Windows payload source files
- Python orchestration code

The repository also includes defensive detection content for Linux and Docker
hosts. The proof-of-concept and payload source files are provided as research
artifacts; use the detection tools below for host triage.

## Prerequisites

- Python 3.8+, `ffmpeg`, `gcc` (or `x86_64-w64-mingw32-gcc` for Windows targets)
- Attacker host reachable from the target (media fetch + reverse shell)

## Detection and triage

The read-only Linux hunt script checks the installed Plex version, Plex
preferences and logs, codec files, and live processes. Run it with
appropriate permissions for the coverage you need:

```sh
bash detection/hunt/plex2shell-hunt.sh
```

To inspect a copied or offline Plex support directory and skip live process
checks:

```sh
bash detection/hunt/plex2shell-hunt.sh \
  -a "/path/to/Library/Application Support/Plex Media Server" -P
```

The script exits with status `0` when it finds no indicators, `1` for warnings
that need review, and `2` when it finds indicator hits. A hit is not by itself
proof of compromise; preserve relevant evidence and investigate in context.
The bundled YARA rules are used automatically when YARA is installed. They can
also be run independently:

```sh
yara -r -w detection/yara/plex2shell.yar \
  "/path/to/Library/Application Support/Plex Media Server"
```

The hunt script does not modify the inspected host. Running it as root gives
it broader visibility into live processes; when investigating a suspected
incident, preserve logs and relevant files before making changes.

## Detection tests

The regression tests use synthetic fixtures and do not compile or load
payloads. They require Bash and YARA 4.2 or later:

```sh
bash detection/tests/run_tests.sh
```

## Improvements I made

- Improved portability when running from Windows by making terminal-specific
  features optional.
- Added retry handling for transient failures and clearer error reporting.
- Added persistent progress tracking so interrupted authorized assessments can
  resume.
- Added optional text or JSON Lines logging for assessment results.
- Improved terminal output when colors or an interactive terminal are
  unavailable.
- Added cooperative shutdown and cleanup for listeners and other resources.
- Added input and dependency checks before starting an assessment.

Logs and saved state may contain sensitive assessment information; store them
with appropriate access controls.

## Mitigation

### Plex administrators

1. Upgrade Plex Media Server to **1.43.3.10861** or later.
2. If you cannot upgrade immediately, restrict access to the Plex server to
   trusted networks and users, and avoid exposing it directly to the internet.
3. Review Plex host and network logs for unexpected outbound requests, file
   changes, or child processes.
4. If compromise is suspected, isolate the host, preserve relevant logs, and
   rotate credentials and tokens available to the Plex service account.
5. After remediation, verify the installed version and review the vendor's
   release information for any additional required steps.

### Network defenders

- Limit inbound access to Plex services to the smallest required set of
  clients and networks.
- Monitor for unusual server-initiated network connections and unexpected
  process activity from the Plex service.
- Keep endpoint protection and host monitoring enabled on systems running
  Plex Media Server.

## Authorized research

This repository is intended for authorized security testing, academic
research, and defensive analysis only. Test only systems you own or have
explicit written permission to assess. Coordinate testing with the system
owner, use an isolated environment where possible, and stop if testing causes
unexpected impact.

## References

- [Plex2shell technical write-up](https://zmain.info/blog/plex2shell)
- [Plex Media Server downloads](https://www.plex.tv/media-server-downloads/)
- [Plex support](https://support.plex.tv/)

## License

GPLv3. See [LICENSE](LICENSE).

## Disclaimer

This project is provided "as is", without warranty of any kind. The authors
are not responsible for misuse, damage, or service disruption. Unauthorized
access to computer systems may be illegal.
