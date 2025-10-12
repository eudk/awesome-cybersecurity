# Awesome Cybersecurity Tools

[![Awesome](https://img.shields.io/badge/Awesome-Cybersecurity-000000.svg?logo=github&labelColor=24292e)](#)
[![Stars](https://img.shields.io/github/stars/eudk/awesome-cybersecurity?style=social)](#)
[![Forks](https://img.shields.io/github/forks/eudk/awesome-cybersecurity?style=social)](#)
[![Last Commit](https://img.shields.io/badge/last%20commit-auto--updated-informational)](#)

A practical, catalog of security tools for students, red/blue teams, and builders. Focus is on widely used, well-maintained, and actually useful software across recon, web/API, cloud, containers, AD, DFIR, and more.

Format inspired by the structure and navigation style of my AI list. This one is tuned for security workflows and fast lookup.

<p align="center">
  <img alt="A futuristic cyber security interface" src="https://images.unsplash.com/photo-1690585703267-de31ea667ef0?q=80&w=1171&auto=format&fit=crop&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D" width="450">
</p>

> Legal and ethical notice: Use these tools only on systems you own or are explicitly authorized to test. Many are dual-use. If you don’t have written permission, don’t touch it. This repository is intended for educational and authorized professional use only. The tools and resources listed here are for learning, security testing, and defensive research in controlled environments.

---

## Navigation

Use your browser’s find (Ctrl+F or Cmd+F) or jump via the table:

| Category                                                                                   | What’s in it                                             |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| [Core / Must-Know](#core--must-know)                                                       | Baseline tooling every security practitioner should know |
| [Recon & Asset Discovery](#recon--asset-discovery)                                         | Discovery, subdomains, screenshots, tech ﬁngerprints     |
| [Port Scanning & Enumeration](#port-scanning--enumeration)                                 | Fast/precise scanning, service probing                   |
| [Web App Testing](#web-app-testing)                                                        | Proxies, fuzzers, SQLi/XSS/dir brute, parameter miners   |
| [API Security](#api-security)                                                              | REST/gRPC fuzzers, schema-based testing                  |
| [CMS & Framework Scanners](#cms--framework-scanners)                                       | WordPress, Drupal, Joomla, general CMS                   |
| [Cloud Security](#cloud-security)                                                          | AWS/Azure/GCP posture, IAM hunting, S3 checks            |
| [Containers & Kubernetes](#containers--kubernetes)                                         | Image scanning, runtime defense, CIS checks              |
| [IaC, SBOM & Dependency Risk](#iac-sbom--dependency-risk)                                  | Terraform checks, SCA, SBOM generation                   |
| [Secrets Detection](#secrets-detection)                                                    | Git and filesystem secrets finders                       |
| [Active Directory & Windows](#active-directory--windows)                                   | Enumeration, LLMNR/NTLM, ADCS, privesc                   |
| [Network, Traffic & MITM](#network-traffic--mitm)                                          | NIDS, packet capture, dissecting, interception           |
| [Wireless & Bluetooth](#wireless--bluetooth)                                               | 802.11 capture/attacks, WPA/PMKID, BLE                   |
| [Mobile Security](#mobile-security)                                                        | Android/iOS reversing, instrumentation                   |
| [Reverse Engineering & Binary](#reverse-engineering--binary)                               | Disassemblers, debuggers, symbolic exec                  |
| [Fuzzing](#fuzzing)                                                                        | AFL-class fuzzers, API fuzzers                           |
| [Credentials, Cracking & Wordlists](#credentials-cracking--wordlists)                      | Hashcat/JtR, spray/bruteforce, lists                     |
| [OSINT & Threat Intel](#osint--threat-intel)                                               | Footprinting, TI platforms, hunting                      |
| [Phishing & Social](#phishing--social)                                                     | Campaign frameworks, kits (defensive research use only)  |
| [C2 & Post-Exploitation](#c2--post-exploitation)                                           | Open C2, operators, pivoting                             |
| [Vuln Scanning & Management](#vuln-scanning--management)                                   | Network/web scanners, template engines                   |
| [DFIR & Forensics](#dfir--forensics)                                                       | Memory, disk, Windows triage, timelines                  |
| [Tunneling, Pivoting & Relays](#tunneling-pivoting--relays)                                | Socks/HTTP tunnels, relay tools                          |
| [Helper Utilities](#helper-utilities)                                                      | CLI helpers that save time                               |
| [Hardware, RF & OT Pentest Tools](#hardware-rf--ot-pentest-tools-flipper-class-and-beyond) | Flipper/Proxmark/SDR, embedded/JTAG, Hak5/O.MG           |
| [Books (Beginner → Advanced)](#books-beginner--advanced)                                   | Curated reading path: foundations, web, RE, DFIR         |
| [Certifications](#certifications-by-level-and-intent)                                      | Entry, offensive, blue team, cloud, governance/privacy   |
| [Hands-On Training Platforms](#hands-on-training-platforms-labs-ranges-ctfs)               | TryHackMe/HTB, PortSwigger, OSINT/DFIR ranges            |
| [Courses & Structured Programs](#courses--structured-programs)                             | Free academic, vendor programs, guided tracks            |
| [Compliance](#compliance-frameworks-how-to-learn-tools-compliance-as-code)                 | ISO/NIST/CIS/GDPR/NIS2/DORA, tools, policy-as-code       |

---

## Conventions

- [F] = Free/Open Source, [C] = Commercial or paid tier available
- OS tags: [Linux] [macOS] [Windows]
- Short on fluff. If you need deep docs, click through.

---

## Core / Must-Know

- [Nmap](https://nmap.org) [F] [Linux macOS Windows] — Network scanner, service/version scripts (NSE).
- [Wireshark](https://www.wireshark.org) [F] [Linux macOS Windows] — Packet capture and protocol analysis.
- [Burp Suite](https://portswigger.net/burp) [F/C] [Linux macOS Windows] — Web proxy, repeater, intruder, extensible.
- [OWASP ZAP](https://www.zaproxy.org) [F] [Linux macOS Windows] — Web proxy/DAST alternative to Burp.
- [Metasploit Framework](https://www.metasploit.com) [F] [Linux macOS Windows] — Exploitation framework and post-exploitation.
- [OpenVAS / Greenbone](https://greenbone.net) [F] [Linux] — Network vuln scanning.
- [ffuf](https://github.com/ffuf/ffuf) [F] [Linux macOS Windows] — Fast web fuzzer for dirs/params/vhosts.
- [sqlmap](https://sqlmap.org) [F] [Linux macOS Windows] — Automated SQL injection/dumping.
- [Hashcat](https://hashcat.net/hashcat) [F] [Linux macOS Windows] — GPU/CPU password cracking.
- [John the Ripper Jumbo](https://www.openwall.com/john/) [F] [Linux macOS Windows] — Password/cracking suite.

[Back to Top](#navigation)

---

## Recon & Asset Discovery

- [Amass](https://github.com/owasp-amass/amass) [F] — Subdomain enum via multiple sources and graphing.
- [Subfinder](https://github.com/projectdiscovery/subfinder) [F] — Passive subdomain discovery.
- [Assetfinder](https://github.com/tomnomnom/assetfinder) [F] — Find subdomains via public sources.
- [httpx](https://github.com/projectdiscovery/httpx) [F] — Fast HTTP probing with metadata.
- [Nuclei](https://github.com/projectdiscovery/nuclei) [F] — Template-based vuln checks; pair with `httpx`.
- [Naabu](https://github.com/projectdiscovery/naabu) [F] — Fast port scanner (SYN).
- [dnsx](https://github.com/projectdiscovery/dnsx) [F] — DNS toolkit (resolve/brute/certs).
- [Aquatone](https://github.com/michenriksen/aquatone) [F] — Site screenshots by domain.
- [gowitness](https://github.com/sensepost/gowitness) [F] — Fast headless browser screenshots.
- [theHarvester](https://github.com/laramies/theHarvester) [F] — Emails, names, subdomains from search engines.
- [Shodan CLI](https://cli.shodan.io) [F/C] — Shodan search from terminal.
- [Censys CLI](https://github.com/censys/censys-python) [F/C] — Censys lookups.

[Back to Top](#navigation)

---

## Port Scanning & Enumeration

- [masscan](https://github.com/robertdavidgraham/masscan) [F] — Very fast Internet-scale scanner.
- [rustscan](https://github.com/RustScan/RustScan) [F] — Rapid scanner that feeds into Nmap.
- [zmap](https://github.com/zmap/zmap) [F] — Single-probe Internet scanner.
- [unicornscan](https://sourceforge.net/projects/unicornscan/) [F] — Legacy but still useful for odd cases.
- [Netcat / ncat](https://nmap.org/ncat/) [F] — Swiss-army knife for TCP/UDP.

[Back to Top](#navigation)

---

## Web App Testing

- [Burp Suite](https://portswigger.net/burp) [F/C] — Intercept, modify, extend (BApp Store).
- [OWASP ZAP](https://www.zaproxy.org) [F] — Good automation and HUD for learning.
- [ffuf](https://github.com/ffuf/ffuf) [F] — Directory/parameter/vhost fuzzing.
- [dirsearch](https://github.com/maurosoria/dirsearch) [F] — Classic content discovery.
- [wfuzz](https://github.com/xmendez/wfuzz) [F] — Flexible web fuzzing.
- [Arjun](https://github.com/s0md3v/Arjun) [F] — Hidden parameter discovery.
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) [F] — Parameter harvesting from URLs.
- [dalfox](https://github.com/hahwul/dalfox) [F] — XSS scanning with smart injection points.
- [XSStrike](https://github.com/s0md3v/XSStrike) [F] — XSS detection and exploitation.
- [tplmap](https://github.com/epinna/tplmap) [F] — Server-Side Template Injection checks.
- [Nikto](https://github.com/sullo/nikto) [F] — Legacy but still useful web scanner.

[Back to Top](#navigation)

---

## API Security

- [RESTler](https://github.com/microsoft/restler-fuzzer) [F] — Smart REST API fuzzing from Swagger/OpenAPI.
- [Schemathesis](https://github.com/schemathesis/schemathesis) [F] — Property-based testing for APIs from schemas.
- [kiterunner](https://github.com/assetnote/kiterunner) [F] — API route discovery.
- [grpcurl](https://github.com/fullstorydev/grpcurl) [F] — gRPC probing.
- [mitmproxy](https://mitmproxy.org) [F] — Intercept TLS traffic; scripts for API testing.

[Back to Top](#navigation)

---

## CMS & Framework Scanners

- [WPScan](https://wpscan.com) [F/C] — WordPress enumeration and vuln checks.
- [droopescan](https://github.com/droope/droopescan) [F] — Drupal/Joomla/CouchCMS checks.
- [joomscan](https://github.com/OWASP/joomscan) [F] — Joomla scanner.

[Back to Top](#navigation)

---

## Cloud Security

- [Prowler](https://github.com/prowler-cloud/prowler) [F] — AWS/Azure/GCP security benchmarking.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) [F] — Multi-cloud posture assessment.
- [CloudQuery](https://github.com/cloudquery/cloudquery) [F] — Cloud inventory to SQL for queries.
- [CloudSploit](https://github.com/aquasecurity/cloudsploit) [F] — Cloud configuration checks.
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) [F] — AWS exploitation framework (authorized research).
- [cloudfox](https://github.com/BishopFox/cloudfox) [F] — CLI to find cloud attack paths.
- [S3Scanner](https://github.com/abhn/S3Scanner) [F] — Public S3 bucket discovery.
- [enumerate-iam](https://github.com/Netflix-Skunkworks/policyuniverse) [F] — IAM policy analysis.

### 2025 Cloud Security Tools Verification Update

| Tool               | Link                                                                                      | Last Commit | Activity       | Still Relevant | License      | Keep/Update/Remove    | Notes                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------- | ----------- | -------------- | -------------- | ------------ | --------------------- | ---------------------------------------------------------------------------------- |
| **Prowler**        | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)                         | Oct 2025    | Very Active    | Yes            | Apache-2.0   | Keep                  | Multi-cloud security & compliance scanner; supports CIS, NIST 800, HIPAA, FedRAMP. |
| **ScoutSuite**     | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)                             | May 2024    | Moderate       | Yes            | GPL-2.0      | Keep (Watch Activity) | Multi-cloud auditing tool; slower updates but still reliable for baseline checks.  |
| **CloudQuery**     | [cloudquery/cloudquery](https://github.com/cloudquery/cloudquery)                         | Oct 2025    | Very Active    | Yes            | MPL-2.0      | Keep                  | ELT & CSPM framework; good for compliance data pipelines (AWS/GCP/Azure).          |
| **CloudSploit**    | [aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit)                   | Oct 2025    | High           | Yes            | GPL-3.0      | Keep                  | CSPM tool from Aqua Security with HIPAA, PCI, and CIS profiles.                    |
| **Pacu**           | [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)                       | Jul 2025    | Active         | Yes            | BSD-3-Clause | Keep                  | AWS exploitation framework for offensive testing and GRC validation labs.          |
| **CloudFox**       | [BishopFox/cloudfox](https://github.com/BishopFox/cloudfox)                               | Aug 2025    | Active         | Yes            | MIT          | Keep                  | Cross-cloud enumeration tool for attack-path and trust analysis.                   |
| **PolicyUniverse** | [Netflix-Skunkworks/policyuniverse](https://github.com/Netflix-Skunkworks/policyuniverse) | 2023        | Low            | Partially      | Apache-2.0   | Replace               | Outdated IAM policy parser; consider IAMbic or Policy Sentry.                      |
| **S3Scanner**      | [abhn/S3Scanner](https://github.com/abhn/S3Scanner)                                       | N/A         | Inactive / 404 | No             | Unknown      | Remove                | Repository gone; replace with AWSBucketDump or Pacu S3 modules.                    |

[Back to Top](#navigation)

---

## Containers & Kubernetes

- [Trivy](https://github.com/aquasecurity/trivy) [F] — Image/filesystem/Repo/IaC scanning.
- [Grype](https://github.com/anchore/grype) [F] — SBOM-driven image vulnerability scanning.
- [Syft](https://github.com/anchore/syft) [F] — SBOM generation (SPDX/CycloneDX).
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) [F] — K8s attack surface discovery.
- [kube-bench](https://github.com/aquasecurity/kube-bench) [F] — CIS K8s benchmarks.
- [Kubescape](https://github.com/kubescape/kubescape) [F] — K8s posture and compliance.
- [Popeye](https://github.com/derailed/popeye) [F] — K8s cluster sanitizer.
- [Falco](https://github.com/falcosecurity/falco) [F] — Runtime threat detection via eBPF.
- [Dockle](https://github.com/goodwithtech/dockle) [F] — Docker image linting.
- [Clair](https://github.com/quay/clair) [F] — Image vulnerability analysis.

[Back to Top](#navigation)

---

## IaC, SBOM & Dependency Risk

- [tfsec](https://github.com/aquasecurity/tfsec) [F] — Terraform static analysis.
- [Checkov](https://github.com/bridgecrewio/checkov) [F] — IaC scanning (Terraform, K8s, Cloud).
- [Terrascan](https://github.com/tenable/terrascan) [F] — Policy-as-code for IaC.
- [Semgrep](https://github.com/semgrep/semgrep) [F] — Code scanning with community rules (supports IaC).
- [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck) [F] — Java/.NET/others dependency CVEs.
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) [F] — SBOM utilities.

[Back to Top](#navigation)

---

## Secrets Detection

- [gitleaks](https://github.com/gitleaks/gitleaks) [F] — Git secrets detection.
- [trufflehog](https://github.com/trufflesecurity/trufflehog) [F] — Secrets in repos, files, and APIs.
- [git-secrets](https://github.com/awslabs/git-secrets) [F] — Prevent committing secrets.
- [detect-secrets](https://github.com/Yelp/detect-secrets) [F] — Pluggable pre-commit secrets scanner.
- [ggshield](https://github.com/GitGuardian/ggshield) [F/C] — CLI with GitGuardian detectors.

[Back to Top](#navigation)

---

## Active Directory & Windows

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) [F] — AD attack path graphing.
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) [F] — AD data collector.
- [Impacket](https://github.com/fortra/impacket) [F] — SMB/RPC/LDAP tooling (psexec, wmiexec, ntlmrelayx).
- [Responder](https://github.com/lgandx/Responder) [F] — LLMNR/NBNS poisoning.
- [mitm6](https://github.com/dirkjanm/mitm6) [F] — IPv6 DNS takeover in AD.
- [Rubeus](https://github.com/GhostPack/Rubeus) [F] — Kerberos abuse (authorized research).
- [Certipy](https://github.com/ly4k/Certipy) [F] — AD CS abuse and enumeration.
- [Coercer](https://github.com/p0dalirius/Coercer) [F] — Force auth via RPC.
- [PetitPotam](https://github.com/topotam/PetitPotam) [F] — EfsRpc relay research.
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) [F] — Lateral movement swiss-army knife.
- [WinPEAS / LinPEAS](https://github.com/carlospolop/PEASS-ng) [F] — Local privesc checks.
- [Seatbelt](https://github.com/GhostPack/Seatbelt) [F] — Windows triage enumeration.
- [PowerView / PowerUp](https://github.com/PowerShellMafia/PowerSploit) [F] — AD recon and privesc.
- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) [F] — Dump AD info via LDAP.

[Back to Top](#navigation)

---

## Network, Traffic & MITM

- [Zeek](https://zeek.org) [F] — Network security monitoring.
- [Suricata](https://suricata.io) [F] — IDS/IPS with rulesets.
- [Snort 3](https://snort.org) [F] — IDS/IPS engine.
- [Arkime (Moloch)](https://arkime.com) [F] — Full-packet capture and indexing.
- [Security Onion](https://securityonionsolutions.com/software/) [F] — NSM distro (Zeek/Suricata/Wazuh).
- [mitmproxy](https://mitmproxy.org) [F] — Interactive TLS proxy with scripting.
- [bettercap](https://www.bettercap.org) [F] — MITM framework and network recon.
- [tcpdump / tshark](https://www.tcpdump.org) [F] — CLI packet capture.

[Back to Top](#navigation)

---

## Wireless & Bluetooth

- [Aircrack-ng](https://www.aircrack-ng.org) [F] — 802.11 capture and key cracking.
- [hcxdumptool / hcxpcapngtool](https://github.com/ZerBea/hcxdumptool) [F] — PMKID/handshake harvesting and conversion.
- [kismet](https://www.kismetwireless.net) [F] — Wireless IDS and surveys.
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x) [F] — WPS attacks (legacy).
- [wifite2](https://github.com/derv82/wifite2) [F] — Automated Wi-Fi attack orchestration.
- [mdk4](https://github.com/aircrack-ng/mdk4) [F] — 802.11 stress/attack testing.
- [BlueZ](http://www.bluez.org) [F] — Linux Bluetooth stack tools.
- [btlejack](https://github.com/virtualabs/btlejack) [F] — BLE sniffing with cheap hardware.

[Back to Top](#navigation)

---

## Mobile Security

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) [F] — Mobile static/dynamic analysis.
- [Frida](https://frida.re) [F] — Dynamic instrumentation.
- [Objection](https://github.com/sensepost/objection) [F] — Runtime mobile exploration (Frida-based).
- [jadx](https://github.com/skylot/jadx) [F] — Android decompiler.
- [apktool](https://ibotpeaches.github.io/Apktool/) [F] — APK decode/rebuild.
- [drozer](https://github.com/WithSecureLabs/drozer) [F] — Android security assessment (older but useful).
- [Xcode / Android Studio](https://developer.android.com/studio) [F] — Official toolchains and emulators.

[Back to Top](#navigation)

---

## Reverse Engineering & Binary

- [Ghidra](https://ghidra-sre.org) [F] — Full suite reverse engineering.
- [Radare2 / Cutter](https://cutter.re) [F] — Disassembler/debugger with GUI.
- [Binary Ninja](https://binary.ninja) [C] — Fast reversing with APIs.
- [IDA Pro](https://hex-rays.com/ida-pro/) [C] — Industry-standard disassembler/debugger.
- [x64dbg](https://x64dbg.com) [F] — Windows debugging.
- [angr](https://angr.io) [F] — Binary analysis with symbolic execution.
- [pwndbg](https://github.com/pwndbg/pwndbg) [F] — Enhanced GDB for pwn.

[Back to Top](#navigation)

---

## Fuzzing

- [AFL++](https://github.com/AFLplusplus/AFLplusplus) [F] — Modernized AFL fork.
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html) [F] — In-process coverage-guided fuzzing (LLVM).
- [Honggfuzz](https://github.com/google/honggfuzz) [F] — General-purpose fuzzer.
- [boofuzz](https://github.com/jtpereyda/boofuzz) [F] — Network protocol fuzzing (Sulley successor).
- [RESTler](https://github.com/microsoft/restler-fuzzer) [F] — API fuzzing from schemas (listed above too).

[Back to Top](#navigation)

---

## Credentials, Cracking & Wordlists

- [Hashcat](https://hashcat.net/hashcat) [F] — GPU/CPU cracking with rule/mask/PRINCE.
- [John the Ripper Jumbo](https://www.openwall.com/john/) [F] — CPU cracking and formats.
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) [F] — Network login bruteforcing.
- [Medusa](https://github.com/jmk-foofus/medusa) [F] — Parallel login brute-forcer.
- [patator](https://github.com/lanjelot/patator) [F] — Flexible brute-forcer/sprayer.
- [hashid](https://github.com/psypanda/hashID) [F] — Identify hash types.
- [cewl](https://github.com/digininja/CeWL) [F] — Custom wordlist generator from sites.
- [crunch](https://sourceforge.net/projects/crunch-wordlist/) [F] — Wordlist generator.
- [hashcat-utils](https://github.com/hashcat/hashcat-utils) [F] — Rule helpers and transforms.
- [SecLists](https://github.com/danielmiessler/SecLists) [F] — Wordlists for fuzzing, creds, payloads.
- [Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists) [F] — Frequency-based lists.

[Back to Top](#navigation)

---

## OSINT & Threat Intel

- [SpiderFoot](https://github.com/smicallef/spiderfoot) [F] — Automated OSINT.
- [Maltego CE](https://www.maltego.com/downloads/) [F/C] — Graph OSINT with transforms.
- [Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) [F] — OSINT framework.
- [GHunt](https://github.com/mxrch/GHunt) [F] — Google OSINT.
- [Photon](https://github.com/s0md3v/Photon) [F] — Fast crawler for intel.
- [MISP](https://www.misp-project.org) [F] — Threat intel platform for IOCs.
- [OpenCTI](https://www.opencti.io) [F] — Threat intel knowledge base.

[Back to Top](#navigation)

---

## Phishing & Social

Research and defense testing only, with explicit authorization.

- [Gophish](https://getgophish.com) [F] — Phishing framework for training/testing.
- [King Phisher](https://github.com/rsmusllp/king-phisher) [F] — Flexible phishing campaigns.
- [Evilginx2](https://github.com/kgretzky/evilginx2) [F] — Adversary-in-the-middle framework for auth research.
- [Modlishka](https://github.com/drk1wi/Modlishka) [F] — Reverse proxy for login flows (research).

[Back to Top](#navigation)

---

## C2 & Post-Exploitation

Operate only in lab or with written authorization. Many tools are detected by EDR by default.

- [Sliver](https://github.com/BishopFox/sliver) [F] — Open C2 framework.
- [Mythic](https://github.com/its-a-feature/Mythic) [F] — Plugin-based C2 with multiple agents.
- [Havoc](https://github.com/HavocFramework/Havoc) [F] — Modern C2.
- [Covenant](https://github.com/cobbr/Covenant) [F] — .NET C2 framework.
- [Empire (BC-Security)](https://github.com/BC-SECURITY/Empire) [F] — PowerShell/C# post-exploitation.
- [PoshC2](https://github.com/nettitude/PoshC2) [F] — PowerShell C2.
- [Merlin](https://github.com/Ne0nd0g/merlin) [F] — Cross-platform agent over HTTP/2.
- [Quasar](https://github.com/quasar/Quasar) [F] — Windows remote admin (research).

[Back to Top](#navigation)

---

## Vuln Scanning & Management

- [OpenVAS / Greenbone](https://greenbone.net) [F] — Infrastructure scanning.
- [Nessus](https://www.tenable.com/products/nessus) [C] — Widely used network scanner.
- [Nuclei](https://github.com/projectdiscovery/nuclei) [F] — Template-based checks at scale.
- [Nikto](https://github.com/sullo/nikto) [F] — Legacy web scanner for quick wins.
- [Dependency-Check](https://github.com/jeremylong/DependencyCheck) [F] — SCA for libraries.
- [Trivy / Grype](#containers--kubernetes) — SCA and container scanning (see above).

[Back to Top](#navigation)

---

## DFIR & Forensics

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) [F] — Memory forensics.
- [Autopsy / Sleuth Kit](https://www.sleuthkit.org/autopsy/) [F] — Disk forensics GUI.
- [Velociraptor](https://github.com/Velocidex/velociraptor) [F] — Endpoint visibility and DFIR.
- [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifacts-parser-extractor-kape) [F] — Targeted triage collection (Windows).
- [plaso / log2timeline](https://github.com/log2timeline/plaso) [F] — Timeline generation.
- [Timesketch](https://github.com/google/timesketch) [F] — Collaborative timeline analysis.
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/#!index.md) [F] — Windows artifact analysis.
- [YARA](https://virustotal.github.io/yara/) [F] — Pattern matching for malware hunting.
- [Sigma + tools](https://github.com/SigmaHQ/sigma) [F] — Generic SIEM rules and converters.
- [Bulk Extractor](https://github.com/simsong/bulk_extractor) [F] — Feature extraction at scale.
- [TestDisk / PhotoRec](https://www.cgsecurity.org) [F] — Recovery of lost files/partitions.

[Back to Top](#navigation)

---

## Tunneling, Pivoting & Relays

- [chisel](https://github.com/jpillora/chisel) [F] — TCP/UDP over HTTP tunneling.
- [ligolo-ng](https://github.com/nicocha30/ligolo-ng) [F] — Reverse tunneling/proxy.
- [frp](https://github.com/fatedier/frp) [F] — Fast reverse proxy.
- [sshuttle](https://github.com/sshuttle/sshuttle) [F] — Poor man’s VPN over SSH.
- [socat](http://www.dest-unreach.org/socat/) [F] — Bidirectional relay swiss-army knife.
- [rinetd](https://github.com/samhocevar/rinetd) [F] — Simple TCP redirection.

[Back to Top](#navigation)

---

## Helper Utilities

- [ripgrep](https://github.com/BurntSushi/ripgrep) — Fast grep replacement.
- [fzf](https://github.com/junegunn/fzf) — Fuzzy finder in terminal.
- [bat](https://github.com/sharkdp/bat) — Better `cat` with syntax highlight.
- [jq / yq](https://stedolan.github.io/jq/) — JSON/YAML processing.
- [httpie](https://httpie.io) — Human-friendly HTTP client.
- [pv](https://www.ivarch.com/programs/pv.shtml) — Pipe progress meter.

[Back to Top](#navigation)

---

## Hardware, RF & OT Pentest Tools (Flipper-class and beyond)

> Legal/ethical: use only on systems you own or have written authorization to test.

- **Flipper Zero** — Portable multi-tool for sub-GHz, NFC/RFID, IR, GPIO, BLE apps; large open ecosystem.  
  https://flipperzero.one
- **Proxmark3 RDV4** — High-end LF/HF RFID research (read/write/snoop/replay/emulate); de-facto standard.  
  https://proxmark.com
- **ChameleonMini/ChameleonUltra** — HF RFID emulator for MIFARE/ISO14443; fast clone/replay labs.  
  https://github.com/emsec/ChameleonMini · https://chameleonultra.com
- **HackRF One** — 1 MHz–6 GHz SDR transceiver for capture/replay, modulation experiments.  
  https://greatscottgadgets.com/hackrf/one
- **LimeSDR (USB/Mini)** — Full-duplex SDR (broadband TX/RX); LTE/LoRa/Zigbee/GSM research.  
  https://myriadrf.org/projects/limesdr
- **RTL-SDR Blog V3** — Ultra-low-cost SDR receiver; spectrum survey, ADS-B, trunking monitoring.  
  https://www.rtl-sdr.com
- **Yard Stick One** — Sub-1 GHz digital RF transceiver for ISM/OOK/FSK labs.  
  https://greatscottgadgets.com/yardstickone
- **Ubertooth One** — Open 2.4 GHz/Bluetooth research; still useful for BLE labs if you have one.  
  https://greatscottgadgets.com/ubertoothone
- **Crazyradio PA** — 2.4 GHz NRF24LU1+ transceiver; wireless peripheral protocol tinkering.  
  https://www.bitcraze.io/products/crazyradio-pa
- **Nordic nRF Sniffer (BLE)** — Real-time BLE capture/debug using nRF dev boards.  
  https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
- **GreatFET One** — General-purpose USB hardware hacking (I²C/SPI/UART/JTAG, signal tools).  
  https://greatscottgadgets.com/greatfet/one
- **Bus Pirate** — Multi-bus interface for I²C/SPI/UART/1-Wire sniffing and bring-up.  
  http://dangerousprototypes.com/docs/Bus_Pirate
- **JTAGulator** — Finds JTAG/UART pins on unknown PCBs; speeds embedded analysis.  
  https://www.grandideastudio.com/jtagulator
- **ChipWhisperer-Lite/Pro** — Side-channel + fault-injection (DPA/glitch) research platform.  
  https://www.newae.com/products/chipwhisperer
- **Saleae Logic (8/16/Pro)** — Logic analyzers with rich protocol decode; gold-standard UX.  
  https://www.saleae.com
- **sigrok + PulseView** — Open protocol decoding suite + GUI for many analyzers.  
  https://sigrok.org
- **Hak5 USB Rubber Ducky** — Keystroke-injection for payload/EDR testing; DuckyScript 3.0.  
  https://shop.hak5.org/products/usb-rubber-ducky
- **Hak5 WiFi Pineapple** — Wireless assessment platform (rogue AP, client probing, WPA workflows).  
  https://shop.hak5.org/products/wifi-pineapple
- **Hak5 LAN Turtle** — Inline implant for remote access/MiTM in controlled engagements.  
  https://shop.hak5.org/products/lan-turtle
- **O.MG Cable / O.MG Plug** — Covert red-team implants for realistic USB attack simulation.  
  https://o.mg.lol

[Back to top](#navigation)

---

## Books (Beginner → Advanced)

### Absolute Beginner / Career On-Ramp

- **Cybersecurity First Principles** — Simple models, threat/defense basics (good for true beginners).  
  https://firstprinciples.uscyberpatriot.org
- **The Basics of Hacking and Penetration Testing (2e) — P. Engebretson** — Lab-driven intro to tooling and method.  
  https://www.elsevier.com/books/the-basics-of-hacking-and-penetration-testing/engebretson/978-0-12-411644-3
- **CompTIA Security+ Study Guide (SY0-701)** — Solid baseline for vocabulary and exam mapping.  
  https://www.comptia.org/certifications/security

### Foundations (Must-read)

- **Security Engineering (3e) — Ross Anderson** — Design, threat models, protocol failures, economics.  
  https://www.cl.cam.ac.uk/~rja14/book.html
- **Serious Cryptography (2e) — JP Aumasson** — Modern crypto for engineers (AEAD, ECC, protocols).  
  https://nostarch.com/serious-cryptography-second-edition
- **Real-World Cryptography — David Wong** — Pragmatic crypto, modern protocols, ZK basics.  
  https://www.manning.com/books/real-world-cryptography
- **The Practice of Network Security Monitoring — R. Bejtlich** — NSM mindset, tools, and workflows.  
  https://nostarch.com/nsm
- **Building Secure & Reliable Systems — Google** — Free; risk, reliability, and security at scale.  
  https://sre.google/books/building-secure-and-reliable-systems/

### Networking, Packets & Blue Team

- **Practical Packet Analysis (3e) — Chris Sanders** — Wireshark/TShark workflows.  
  https://nostarch.com/packetanalysis3
- **Windows Internals (7e, Part 1 & 2)** — Core OS internals for detection/DFIR depth.  
  https://learn.microsoft.com/sysinternals/resources/windows-internals
- **Linux Hardening in Hostile Networks — K. Fox** — Practical hardening for real machines.  
  https://nostarch.com/linuxhardening

### Web/AppSec

- **The Web Application Hacker’s Handbook (2e) — Stuttard & Pinto** — Methodical web testing.  
  https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%2C+2nd+Edition-p-9781118026472
- **The Tangled Web — M. Zalewski** — Browser/web platform security internals.  
  https://nostarch.com/tangledweb
- **API Security in Action — N. Mykyta** — Practical API threats and defenses.  
  https://www.manning.com/books/api-security-in-action

### Reverse Engineering, Exploit Dev & Malware

- **The Ghidra Book (2e) — Eagle & Nance** — RE workflows in Ghidra.  
  https://nostarch.com/ghidra2
- **Practical Binary Analysis — Andriesse** — Instrumentation, taint, lifting.  
  https://nostarch.com/binaryanalysis
- **Practical Malware Analysis — Sikorski & Honig** — Classic malware triage/RE.  
  https://nostarch.com/malware
- **Black Hat Python (2e) — Seitz & Arnold** — Offensive tooling patterns in Python 3.  
  https://nostarch.com/black-hat-python2
- **The Art of Memory Forensics — Ligh et al.** — Windows/Linux/OS X memory forensics.  
  https://www.wiley.com/en-us/The+Art+of+Memory+Forensics-p-9781118825099
- **Practical Reverse Engineering — Dang et al.** — Low-level Intel/ARM/RE patterns.  
  https://www.wiley.com/en-us/Practical+Reverse+Engineering-p-9781118787311

### Architecture, Threat Modeling & Culture

- **Threat Modeling — Adam Shostack** — Processes and patterns to design safer systems.  
  https://www.wiley.com/en-us/Threat+Modeling-p-9781118809990
- **Secure by Design — Mosher, tendean, de Win** — Design patterns to avoid whole classes of vulns.  
  https://www.manning.com/books/secure-by-design
- **Designing Data-Intensive Applications — Kleppmann** — Consistency, fault tolerance, data flows that impact security.  
  https://dataintensive.net

### Free Standards/Guides (bookmark)

- **OWASP WSTG** — End-to-end web testing methodology. https://owasp.org/www-project-web-security-testing-guide/
- **OWASP ASVS** — Web security requirements catalog. https://owasp.org/ASVS/
- **NIST SP 800-115** — Technical security testing guide. https://csrc.nist.gov/publications/detail/sp/800-115/final

[Back to top](#navigation)

---

## Certifications (by level and intent)

> Get what your target role requires; hands-on > theory for pentest/DFIR roles.

### Entry / Baseline

- **ISC2 CC (Certified in Cybersecurity)** — Free training + low-cost exam; broad fundamentals. https://www.isc2.org/Certifications/CC
- **CompTIA Security+ (SY0-701)** — Common baseline for junior analyst/consultant. https://www.comptia.org/certifications/security
- **eJPT v2 (INE/eLearnSecurity)** — Practical junior pentest exam. https://ine.com/certifications/ejpt-certification

### Offensive / Pentest / Red Team

- **OSCP / OSWE / OSEP (OffSec)** — Network/web/EDR-aware offense; proctored labs. https://www.offsec.com
- **PNPT (TCM Security)** — Realistic AD-centric pentest with report & debrief. https://certifications.tcm-sec.com/pnpt/
- **CRTO I/II (Zero-Point Security)** — Cobalt Strike-based red team operator. https://www.zeropointsecurity.co.uk/courses
- **eCPPT / eWPT / eWPTX (eLearnSecurity)** — Web/app exploitation tracks. https://ine.com
- **GPEN (SANS/GIAC)** — Pentest methodology & tooling. https://www.giac.org/certifications/gpen/

### Blue Team / DFIR / Detection

- **GCIH / GCIA / GMON / GCFA / GREM (GIAC)** — Incidents, IDS, monitoring, forensics, malware. https://www.giac.org
- **BTL1/BTL2 (Security Blue Team)** — Practical SOC/blue-team labs & exams. https://www.securityblue.team
- **SC-200 (Microsoft)** — Security Operations Analyst (Defender/Sentinel). https://learn.microsoft.com/credentials/certifications/exams/sc-200/

### Cloud & Platform

- **AWS Security – Specialty** — Depth in AWS security. https://aws.amazon.com/certification/
- **Azure AZ-500 / SC-100** — Security Engineer + Cybersecurity Architect Expert. https://learn.microsoft.com/credentials/
- **Google Professional Cloud Security Engineer** — GCP security design/ops. https://cloud.google.com/certification
- **CKS (Kubernetes Security Specialist)** — K8s defensive hardening. https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist-cks/

### Governance / Privacy / Audit

- **CISSP (ISC2)** — Broad management/architecture. https://www.isc2.org/certifications/cissp
- **CISM / CISA (ISACA)** — Management and audit tracks. https://www.isaca.org/credentialing
- **CCSP (ISC2)** — Cloud security architecture. https://www.isc2.org/certifications/ccsp
- **IAPP CIPP/E / CIPM** — GDPR/privacy and program management. https://iapp.org/certify/

[Back to top](#navigation)

---

## Hands-On Training Platforms (labs, ranges, CTFs)

- **TryHackMe** — Guided, browser-based labs; structured paths from beginner to intermediate. https://tryhackme.com
- **Hack The Box** — Challenge boxes, Pro Labs, Academy modules, CPTS/CWEs. https://www.hackthebox.com
- **PortSwigger Web Security Academy** — Best free interactive web labs with theory. https://portswigger.net/web-security
- **OverTheWire** — Classic wargames (Bandit, Narnia, Krypton). https://overthewire.org
- **picoCTF** — Beginner-friendly, CMU-run CTF platform. https://picoctf.org
- **Root-Me** — Large bank of web/crypto/reversing/forensics challenges. https://www.root-me.org
- **CyberDefenders** — Blue-team SOC/DFIR hunt labs with real data. https://cyberdefenders.org
- **Blue Team Labs Online (BTLO)** — Incident-style challenges for SOC analysts. https://securityblue.team/btlo
- **LetsDefend** — SOC simulator with alert triage/detection tasks. https://letsdefend.io
- **RangeForce** — Hands-on cyber skills platform (blue/red). https://www.rangeforce.com
- **Immersive Labs** — Enterprise hands-on labs (skills validation). https://www.immersivelabs.com
- **VulnHub** — Downloadable vulnerable VMs for local labs. https://www.vulnhub.com
- **Malware Traffic Analysis** — PCAP-centric IR investigations. https://www.malware-traffic-analysis.net
- **Flare-On (archive)** — Annual RE/malware challenge set. https://www.flare-on.com

[Back to top](#navigation)

---

## Courses & Structured Programs

### Free / Open Academic

- **MIT 6.858 Computer Systems Security** — Research-grade systems security (OCW).  
  https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/
- **Stanford CS155 Computer & Network Security** — Public materials & past lectures.  
  https://cs155.stanford.edu
- **OpenSecurityTraining & OST2** — Deep dives in RE, exploitation, CPU arch.  
  https://opensecuritytraining.info · https://ost2.fyi
- **Georgia Tech OMSCS (InfoSec)** — Graduate-level content, open syllabi.  
  https://omscs.gatech.edu

### Vendor/Platform Programs

- **OffSec** — Labs-first (PWK/OSCP, AWAE/OSWE, OSEP). https://www.offsec.com
- **SANS / GIAC** — Premium courses; maps directly to GIAC. https://www.sans.org
- **HTB Academy** — Modular courses + hands-on labs + certs. https://academy.hackthebox.com
- **INE/eLearnSecurity** — eJPT/eCPPT/eWPT tracks, cloud & blue team. https://ine.com
- **PentesterLab** — High-quality web vulns bootcamps (burp, auth, serialization, etc.). https://pentesterlab.com
- **Coursera/edX Security Specializations** — Google/IBM/Cisco intro paths (cheap on ramp).  
  https://www.coursera.org · https://www.edx.org

[Back to top](#navigation)

---

## Compliance (Frameworks, How to Learn, Tools, Compliance-as-Code)

> Goal: understand frameworks, map controls to real telemetry, automate evidence, and continuously monitor. EU-centric bits included (NIS2/GDPR/DORA).

### Core Frameworks & Standards (know these)

- **ISO/IEC 27001:2022** — ISMS certification standard; Annex A controls; pair with **27002:2022** for guidance.  
  https://www.iso.org/standard/27001
- **NIST Cybersecurity Framework (CSF) 2.0** — High-level Identify-Protect-Detect-Respond-Recover functions; profiles/tiers.  
  https://www.nist.gov/cyberframework
- **NIST SP 800-53 Rev.5** — Catalog of security/privacy controls (US-centric but broadly referenced).  
  https://csrc.nist.gov/publications/sp
- **CIS Controls v8** — 18 prioritized safeguards + IG1/IG2/IG3 maturity.  
  https://www.cisecurity.org/controls
- **SOC 2 (AICPA TSC)** — Trust Services Criteria (security, availability, processing integrity, confidentiality, privacy).  
  https://www.aicpa.org
- **PCI DSS v4.0** — Cardholder data security for merchants/service providers.  
  https://www.pcisecuritystandards.org
- **GDPR** — EU data protection regulation (law; not a cert).  
  https://gdpr.eu
- **NIS2 Directive (EU)** — Security of network & information systems; risk management & reporting for “essential/important” entities.  
  https://eur-lex.europa.eu
- **DORA (EU financial sector)** — Digital Operational Resilience Act; ICT risk for financial entities.  
  https://finance.ec.europa.eu/dora
- **HIPAA Security Rule (US healthcare)** — ePHI safeguards.  
  https://www.hhs.gov/hipaa
- **Kubernetes Hardening (NSA/CISA)** — Practical K8s hardening guidance—tie to CIS K8s Benchmarks.  
  https://www.cisa.gov/resources-tools

### How to Learn Compliance (practical track)

1. **Pick two frameworks**: one management (**ISO 27001** or **NIST CSF**) + one technical (**CIS Controls** or **800-53**). Learn their structure and vocabulary.
2. **Scope & asset inventory**: define boundaries; build an inventory (devices, apps, data flows, cloud accounts). Tools: **osquery**, **Open-AudIT**, **CloudQuery**.
3. **Risk management basics**: simple risk register (asset, threat, likelihood, impact, control). Use **ISO 27005** or **NIST 800-30** as structure.
4. **Control mapping**: create a control matrix mapping ISO 27001 Annex A ↔ CIS Controls ↔ NIST CSF. Keep it in Git (CSV/Markdown).
5. **Select policies**: start with **Acceptable Use, Access Control, Logging/Monitoring, Incident Response, Change Management, Secure Dev**. Version them in Git; link each to controls in your matrix.
6. **Implement telemetry**: enable logs & metrics that prove controls (e.g., MFA enforced, admin actions audited, EDR coverage %). Prefer **Elastic/OSSEC(Wazuh)/Defender/Sentinel** in labs.
7. **Evidence collection**: automate screenshots, config exports, and queries (e.g., Azure AD sign-in risk policy, AWS Config conformance). Store in a timestamped evidence folder per control.
8. **Continuous control monitoring (CCM)**: pick 10 controls (MFA, patch SLAs, backups tested, encryption at rest, etc.). Automate daily checks with **osquery**, **Wazuh**, cloud configs, and IaC scanners.
9. **Internal audit & SOA**: for ISO, maintain a Statement of Applicability; schedule internal audits; track corrective actions in an issue tracker (Jira/GitHub).
10. **Tabletop & incident drills**: run 2–3 tabletop exercises (ransomware, credential compromise, lost laptop). Record lessons learned as evidence for governance clauses.

### GRC & Evidence Management (open-source first)

- **eramba (Community Edition)** — Open-source GRC (policies, risk, audits, compliance). https://www.eramba.org
- **OpenControl / Compliance-Masonry** — YAML-based control catalogs & docs (FedRAMP origins; still useful conceptually). https://open-control.org
- **OSCAL (NIST)** — Machine-readable security controls (XML/JSON/YAML) to model systems and assessments. https://pages.nist.gov/OSCAL/
- **Documize / Git + Markdown** — Lightweight policy repository with versioning; simple beats bloated.

### Technical Compliance & Benchmark Scanners

- **OpenSCAP + SCAP Security Guide (SSG)** — Automated config scans & remediations for Linux/Windows; DISA/STIG/PCI/GDPR profiles.  
  https://www.open-scap.org · https://github.com/ComplianceAsCode/content
- **Lynis** — Host auditing for Unix/Linux; good for baseline hardening. https://cisofy.com/lynis/
- **CIS-CAT Lite** — Free scanner for CIS Benchmarks (subset of Pro). https://www.cisecurity.org/cis-cat-lite
- **Prowler** — AWS/Azure/GCP security & compliance checks (CIS, NIST, ISO mappings). https://github.com/prowler-cloud/prowler
- **ScoutSuite** — Multi-cloud posture assessment. https://github.com/nccgroup/ScoutSuite
- **CloudSploit (Aqua)** — Cloud config checks (CIS). https://github.com/aquasecurity/cloudsploit
- **Steampipe + Mods** — Query clouds/SaaS with SQL; ready-made compliance dashboards. https://steampipe.io
- **kube-bench** — CIS Kubernetes Benchmark checks. https://github.com/aquasecurity/kube-bench
- **Kubescape** — K8s posture/compliance incl. NSA/CISA hardening. https://github.com/kubescape/kubescape

### Policy-as-Code / Compliance-as-Code (shift-left)

- **Open Policy Agent (OPA) / Gatekeeper** — Rego policies for K8s admission & CI checks. https://www.openpolicyagent.org
- **Kyverno** — Native K8s policy engine with rich policy packs. https://kyverno.io
- **Conftest** — Test structured configs (YAML/JSON/HCL) with OPA/Rego in CI. https://www.conftest.dev
- **Checkov** — IaC static analysis (Terraform/K8s/Cloud/CloudFormation). https://www.checkov.io
- **tfsec** — Terraform static analysis (now part of Trivy). https://github.com/aquasecurity/tfsec
- **Regula** — Policy-as-code for Terraform/Cloud; maps to CIS/NIST (Fugue/Snyk). https://github.com/fugue/regula
- **Terrascan** — IaC security and compliance scanning. https://github.com/tenable/terrascan
- **OPA Gatekeeper Library** — Prebuilt constraint templates/policies. https://github.com/open-policy-agent/gatekeeper-library

### Continuous Control Monitoring (endpoint/logging)

- **osquery** — SQL over system state; schedule compliance queries (disk encryption, firewall, admin users). https://osquery.io
- **Wazuh** — Open-source SIEM/XDR with PCI/HIPAA rules, FIM, CIS checks. https://wazuh.com
- **Elastic Security (ELK)** — SIEM & detection; map rules to MITRE & compliance. https://www.elastic.co/security
- **Microsoft Defender + Sentinel** — If you’re in Azure/M365 (student-friendly lab licenses exist). https://learn.microsoft.com/azure/sentinel/

### Cloud-Native Governance

- **AWS**: Organizations, Control Tower, Config, Security Hub, Audit Manager, Macie, GuardDuty. https://aws.amazon.com/security
- **Azure**: Policy, Defender for Cloud, Purview (data governance), Blueprints. https://azure.microsoft.com
- **Google Cloud**: Security Command Center, Policy Controller (OPA Gatekeeper), Cloud Asset Inventory. https://cloud.google.com/security
- **Kubernetes**: Admission controls + PSP replacements (OPA/Kyverno), CIS Benchmark via kube-bench.

### Privacy (EU-centric)

- **GDPR text + EDPB guidelines** — Interpretations for DPIA, DPO, consent, transfers. https://edpb.europa.eu
- **IAPP** — Solid primers and mappings (CIPP/E). https://iapp.org

### Templates & Starters (use, then customize)

- **Policy Starter Kits** — SANS Security Policy Templates; CIS sample policies.  
  https://www.sans.org/information-security-policy/ · https://www.cisecurity.org/insights/white-papers
- **Incident Response** — NCSC-UK IR guidance & playbooks; CISA tabletop templates.  
  https://www.ncsc.gov.uk/collection/incident-management · https://www.cisa.gov
- **Risk Register & SoA** — Keep simple CSV/Markdown in Git; link each row to evidence and control IDs.

### Student Lab Checklist (ISO-27001-ish mini ISMS)

- Scope a small lab (laptop, Kali VM, Windows VM, small cloud account).
- Create a lightweight **ISMS folder**: Policies/, RiskRegister.csv, Assets.csv, ControlMatrix.csv, Evidence/.
- Enforce MFA, BitLocker/FileVault, baseline firewall, auto-patch, EDR.
- Enable central logging (**Wazuh/Elastic**), document retention.
- Run **Lynis/OpenSCAP** on hosts; **Prowler/ScoutSuite** on cloud; **kube-bench** if you use K8s.
- Monthly: audit users/admins, key rotation, backup restore test, tabletop IR scenario.

[Back to top](#navigation)
