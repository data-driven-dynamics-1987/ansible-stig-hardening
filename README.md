# ansible-stig-hardening

Provision two DigitalOcean droplets and apply a DISA STIG baseline to both
using a **single Ansible playbook**, driven from a Rocky Linux control node
over SSH trust. Built for Full Sail University's Project & Portfolio VII
(term 2609) and extending the earlier
[ansible-wordpress](https://github.com/data-driven-dynamics-1987) automation
work.

The goal is maximum automation with zero manual per-host steps: one command
stands up both machines, hardens them identically, and produces a compliance
report proving the two systems reached the same state.

## Architecture

```
┌────────────────────────────┐         SSH (key: Charles-Tull-2609)
│  Control node              │────────────────────────┐
│  Rocky Linux 9             │                         │
│  VMware Fusion             │              ┌──────────▼──────────┐
│  Ansible 2.9               │              │  TullC-2609-STIG1   │
└────────────────────────────┘              │  Rocky Linux 8      │
             │                              │  DigitalOcean       │
             │                   ┌──────────▼──────────┐
             └───────────────────│  TullC-2609-STIG2   │
                                 │  Rocky Linux 8      │
                                 │  DigitalOcean       │
                                 └─────────────────────┘
```

- **Control node:** Rocky Linux 9 in VMware Fusion, Ansible pinned to 2.9.
- **Targets:** two DigitalOcean droplets running Rocky Linux 8 (clean RHEL-8
  STIG mapping). Spec each: 1 vCPU, 1 GB RAM, 25–30 GB disk.
- **Trust:** passwordless SSH using the `Charles-Tull-2609` key pair.
- Two identical targets are used to validate that the playbook produces the
  same hardened outcome on both.

## Repository layout

```
ansible-stig-hardening/
├── README.md
├── .gitignore
├── playbooks/            # Ansible playbook(s) and roles
└── docs/
    ├── generate_report.py           # builds the HTML compliance report
    ├── stig-report.html             # rendered compliance report
    ├── CTull_Final_Project_Report.pdf
    └── images/                      # screenshots / diagrams
```

## Prerequisites

- A DigitalOcean account and API token
- Ansible 2.9 on the control node (`ansible --version` to confirm)
- The `community.general` collection for DigitalOcean modules
- An SSH key pair named `Charles-Tull-2609` added to DigitalOcean

## Usage

1. **Set your DigitalOcean token** (kept out of git — see `.gitignore`):

   ```bash
   export DO_API_TOKEN="your_token_here"
   ```

2. **Run the playbook** — provisions both droplets and applies the STIG
   baseline in one pass:

   ```bash
   ansible-playbook playbooks/site.yml
   ```

3. **Generate the compliance report** from the run results:

   ```bash
   cd docs
   python3 generate_report.py results.json stig-report.html
   ```

   With no results file, `generate_report.py` renders from built-in sample
   data so you can preview the report format.

## STIG baseline

The playbook applies 25 DISA RHEL-8 STIG controls covering:

- **Access & authentication** — disable root SSH login, `pam_faillock`
  lockout, SHA-512 password hashing, 15-character minimum length, account
  inactivity locking
- **SSH hardening** — strong ciphers/MACs only, idle-session timeout, DoD
  login banner
- **Boot & kernel** — GRUB password, single-user-mode authentication,
  disabled USB storage, audit rules enabled at boot
- **Auditing** — `auditd` enabled, setuid and privileged-command auditing
- **Network & services** — `firewalld` default-deny, removal of `telnet`
  and `tftp` servers, disabled Ctrl-Alt-Del reboot
- **Crypto & integrity** — FIPS mode, repo GPG signature enforcement

See `docs/stig-report.html` for the full per-host pass/fail breakdown.

## Notes

Credentials and machine-specific artifacts are excluded from version control.
Screenshots included in `docs/images/` have sensitive values redacted.

---

Charles Tull · B.S. Information Technology, Full Sail University
