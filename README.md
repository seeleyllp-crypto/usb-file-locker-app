# USB File Locker App

USB File Locker App is a Windows desktop toolkit for locking files and folders with a USB key, keeping a personal vault, reviewing privacy-safe audit logs, and watching for suspicious access patterns.

The Audit Log Viewer can upload its approved privacy-safe report fields to the licensed Railway API and immediately download a signed JSON copy. Its explicit `AUTO-UPLOAD EVERY 15 MIN` option sends a new snapshot only when meaningful audit or Defender state changes. The API stores a breach summary with each report. Owners can open `API LOGS` in the License Issuer to list and download stored reports later. The server never receives raw files, file contents, USB secrets, passwords, PINs, client names, or full paths.

The main app's `BUG CENTER` lets a customer explicitly send a category, subject, description, and optional reproduction steps to the owner. No files or local logs are attached automatically. Ticket text is encrypted at rest; the server stores an anonymous machine hash instead of a PC name or raw machine id. Customers can check owner replies from the same licensed PC. The owner can acknowledge, mark in progress, resolve, close, reply, keep a private note, or permanently delete a ticket from the owner website.

The API also provides a public `/shop` page for all seven ranks. Buy buttons appear only for allowlisted provider-hosted HTTPS checkout links, so VaultLink never collects card numbers. A missing or invalid checkout link stays visibly unavailable. Payment confirmation and license issuance remain separate owner actions; this release does not claim automatic fulfillment.

`OWNER NEWS` opens rank-targeted announcements published from the owner website. New messages and non-normal service notices also appear automatically on screen once per PC after a successful license sync. These messages are read-only text, require an active license, respect scheduled start and expiration times, and cannot execute commands, access files, or change settings. Only anonymous announcement IDs are saved to prevent repeat popups. `SHOP` opens the public shop without placing the license key or activation receipt in the URL.

## First run

Double-click any `Run ... .bat` launcher. `Ensure Dependencies.cmd` checks for Python 3.9 or newer and imports the pinned `cryptography` package. If that package is missing, the launcher installs it from `requirements.txt`, verifies the import, and then opens the selected app. The first setup needs an internet connection; later starts do not reinstall it.

The app checks the API at startup when its daily update check is due. License state has a separate automatic API heartbeat: it checks about every 60 seconds, follows the server's bounded refresh policy, and re-checks stale state before a premium action. Revoked, expired, reset, removed-device, or deactivated receipts disable premium controls without requiring License Center. A temporary outage keeps a still-valid cached receipt usable within the existing offline grace period. Update Center verifies an Ed25519 manifest signature and SHA-256 package hash, clearly shows the current release, backs up replaced app files, and preserves everything in `%LOCALAPPDATA%\USBFileLocker`. `AUTO-INSTALL VERIFIED UPDATES` is a visible local opt-in; when enabled, a verified update downloads, verifies again, closes the app, installs, and restarts without an extra prompt. Automatic installation remains disabled inside Git working folders; use `git pull` there.

Release `2026.07.14.6` adds Incident Response Center. It combines eight coarse local Defender, audit, owner-USB, key, signed-update, backup, and recovery checks into an explainable 100-point readiness score. Twelve fixed playbooks provide seventy-two concrete steps for Defender alerts, possible account theft, a lost master USB, unlock failure, unknown PC behavior, update integrity problems, device loss, phishing, ransomware warnings, exposed secrets, browser changes, and backup failures. Customers can mark session-only progress, open Windows Security and trusted VaultLink tools, copy a safe summary, and export reviewed JSON. The browser workspace also copies the next fixed step and prints a clean checklist. The center never quarantines, deletes, uploads, scans, or remotely controls a PC.

API `0.29.0` adds `/incident-response` and `/api/v1/incident-guide`. The responsive public workspace accepts no free-form incident text or files, keeps checklist progress only in the current browser tab, and returns no customer records. Apps Hub now contains sixteen compact tools, same-PC Local Control launches fifteen approved apps, and the owner Customer Experience Console sees only aggregate readiness for ten public surfaces. Incident exports exclude license proof, identities, passwords, PINs, USB secrets, paths, filenames, screenshots, process lists, and file contents.

Release `2026.07.14.5` adds Diagnostics Center with eighteen explainable, read-only checks totaling 100 points. It reviews the Python runtime, encryption dependency, required app files, app-data access, working disk space, settings, audit integrity, Defender protection and signature age, owner USB policy, selected key availability, separate Local Control PIN, license state, public diagnostics API, clock sync, signed release, recovery test, and app-data backup. Customers can filter by category or attention state, copy a safe summary, and export a strict privacy-safe JSON report.

API `0.28.0` adds a public `/diagnostics` browser workspace backed by `/api/v1/diagnostics-guide`. It contains eight fixed problem categories and forty concrete troubleshooting steps. Checklist progress stays only in the current browser tab and is never uploaded or saved in browser storage. The public guide accepts no free text or files. Apps Hub now has fifteen compact tools, and same-PC Local Control can launch fourteen approved apps. Diagnostic exports exclude license keys, receipts, customer and machine identity, paths, PINs, USB secrets, filenames, vault data, file contents, and unreviewed exception details.

Release `2026.07.14.4` added Trust & Recovery Center, an explainable 100-point local readiness report combining coarse Microsoft Defender status, audit-chain integrity, owner USB policy, selected-key availability, separate Local Control PIN readiness, license state, signed-update status, public API trust, and recorded recovery and backup tests. It exports only a strict privacy-safe JSON schema: no license keys, receipts, customer identity, paths, PINs, key material, filenames, or file contents.

The public `/trust` page and owner-only `/owner/trust` console expose scored service, release-signature, package-hash, storage, encryption, audit, recovery, and privacy-boundary checks through API `0.27.0`. Public output contains no customer records or license proof; owner output is aggregate-only and requires the admin header. Local Control now offers thirteen approved apps, task-category filters, uptime and session metrics, per-app success/failure totals, a CSRF-protected safe JSON report, and stronger browser isolation and permissions headers. Apps Hub is reorganized into a compact twelve-app grid.

Release `2026.07.14.3` expanded Local Control Center into a same-PC dashboard for twelve approved customer apps. Apps are grouped by core, recovery, private-work, privacy, and monitoring tasks with live package-availability checks. The page shows only coarse license, plan, desktop, API, service, update, runtime, USB, and session status. Customers can refresh status, extend the session, clear a bounded twenty-entry in-memory launch history, copy the loopback URL, or lock the browser session from the desktop window. Removing or changing the selected USB automatically locks browser control.

The controller remains bound only to `127.0.0.1`, uses the separate Windows-protected scrypt control PIN, rechecks the USB and CSRF token before each approved launch, and rate-limits failed logins. Its launch history contains only approved action IDs, labels, UTC timestamps, and success states and disappears when the server stops. It cannot choose files, capture encryption PINs, unlock data, accept remote connections, or execute arbitrary commands.

Release `2026.07.14.2` is the Customer Success and Local Control update. Customer Workspace now adds a six-factor operational score, 30-day success plan, rank benefit map, action filters, unlocked-tool search, and separate privacy-safe support-pack and offline-recovery-card exports. The owner `/owner/customers` console adds an aggregate experience score, customer-journey stages, renewal buckets, rank percentages, customer-surface readiness, and journey CSV export.

The new Local Control Center starts a website only on `127.0.0.1` on the same PC. It requires the selected master USB key to remain present plus a separate 6-64 character control PIN stored only as a Windows-protected scrypt verifier. The controller rate-limits failed PIN attempts, uses CSRF protection and a 15-minute session, and can launch only eight approved VaultLink desktop apps. It cannot receive remote connections, upload keys or PINs, execute arbitrary commands, or lock and unlock files in the browser. File work still happens in the normal desktop windows with their existing confirmations.

Release `2026.07.14.1` introduced the composite Customer Workspace and aggregate Customer Experience Console. It combined account health, anonymous seats, signed release status, a nine-item prioritized action plan, unlocked rank tools, milestones, upgrades, and customer routes without returning customer identity, license proof, machine identity, receipts, paths, PINs, USB secrets, or file contents.

Release `2026.07.13.5` lets the private Owner Update Lab extract and run the exact verified candidate in a visibly marked OWNER LAB runtime without publishing or replacing the stable app. Each launch re-verifies the signed manifest and package hash, uses a fresh private runtime folder, and keeps only a bounded set of old runtimes. Update installation and file-association changes are disabled in OWNER LAB mode. The runtime uses the normal Windows user data so the real license, USB key, lock, unlock, and companion-app workflows can be tested.

Release `2026.07.13.4` expands Vault Health Center with an update-preserved local aggregate baseline, automatic drift warnings, key-folder coverage, attention-only filtering, and one-click privacy-safe summaries. Baselines and copied summaries contain no filenames, paths, key IDs, secrets, PINs, license data, or file contents. The baseline is local to the Windows account and can be replaced or cleared from the app. Signed updates continue to preserve keys, licenses, settings, vault data, audit logs, locked files, and the health baseline.

Release `2026.07.13.3` adds the customer Vault Health Center for read-only locked-file structure checks, legacy-format review, recovery status, multi-key coverage, safe scan cancellation, and aggregate snapshot comparison. Its reports exclude filenames, paths, key IDs, secrets, and file contents. It also expands the customer Update Center with signed release identity, verified SHA-256 copy, verification receipts, local readiness checks, verified download-only mode, anonymous update activity, rollback-backup access, and app-data backup. The private Owner Update Lab includes a 15-check preflight, signed-package inspection, report export, hash-chained release history, candidate-folder access, and owner shortcuts. Owner tools remain excluded from customer ZIPs. Signed updates preserve keys, licenses, settings, vault data, audit logs, and locked files.

Release `2026.07.13.2` adds a private local Owner Update Lab. `TEST CANDIDATE` builds and signs outside the live API repo, runs both regression suites, verifies the Ed25519 manifest and ZIP hash, checks package contents, and scans the app, API, and candidate with Microsoft Defender. `PUBLISH VERIFIED UPDATE` repeats those gates, publishes the exact tested files through the pinned GitHub repositories, waits for Railway, and verifies the live download hash. Both actions require the registered removable owner USB and Windows-protected signing key. The lab and its launcher are deliberately excluded from customer update ZIPs; the customer app shows its launcher only in the local owner source folder. The API independently verifies the release signature as well as the package size and SHA-256 hash. Updates still replace app files only and preserve keys, licenses, settings, vault data, and audit logs in `%LOCALAPPDATA%\USBFileLocker`.

The Owner Update Lab also includes a 15-check read-only preflight, signed-package content inspection, SHA-256 copy, privacy-safe JSON report export, hash-chained release history, candidate-folder access, and shortcuts to the live Owner Console, Update Center, and pinned app/API GitHub repositories. Its reports and history exclude USB secrets, key paths, signing keys, passwords, PINs, license keys, customer data, file contents, and LocalAppData paths.

## Main desktop apps

- `usb_file_locker.py` - main locker window
- `customer_hub.py` - privacy-safe customer workspace with account health, action plan, rank tools, and safe export
- `incident_response_center.py` - fixed incident playbooks, coarse local readiness, trusted tool shortcuts, and reviewed safe export
- `diagnostics_center.py` - eighteen read-only runtime, storage, Defender, audit, USB, service, update, and recovery checks
- `local_control_center.py` - loopback-only website launcher protected by USB presence and a separate local control PIN
- `trust_recovery_center.py` - scored local trust, signed-update, Defender, audit, backup, and recovery-readiness report
- `privacy_safety_hub.py` - dashboard and safety controls
- `personal_vault_pad.py` - simpler personal vault window
- `audit_log_viewer.py` - signed audit trail viewer
- `license_issuer.py` - owner-only API license issuer; the admin token is masked and never saved
- `global_breach_guard.py` - topmost watcher for repeated risky events
- `text_log_processor.py` - cleans up pasted text-style logs
- `locked_file_browser.py` - finds locked files fast
- `perm_unlock_workbench.py` - edit and relock workflow
- `key_inspector.py` - inspects owner and USB key setup
- `quick_lock_note.py` - makes locked notes quickly
- `vaultlink_updater.py` - separate signed-package installer that runs after the main app closes
- `build_signed_update.py` - owner release builder; requires the DPAPI-protected signing key stored outside GitHub
- `owner_update_lab.py` - local-only owner test and publish console; excluded from customer update packages

## API folder

The public Railway-ready API lives in:

- `usb_locker_api/`

That folder is also safe to copy into its own separate repo if you want a standalone API project.

## Issuing licenses

Run `Run License Issuer.bat` or open License Center and choose `ISSUER APP`. Enter the Railway `LICENSE_ADMIN_TOKEN`, choose one of the seven visible ranks, set its maximum device count, add an optional private owner note, and issue the key. The API enforces that device limit with anonymous machine hashes. `KEYS + NOTES WEBSITE` opens the owner console, where the same admin token can view dashboard totals, anonymous desktop-version adoption and 24-hour sync freshness, shop readiness, scheduled rank-targeted Owner Announcements, informational service status, the tamper-evident API activity chain, anonymous device seats, encrypted-at-rest keys and notes, revocation controls, the Bug Inbox, privacy-safe audit logs, and time-limited giveaway licenses. Giveaway issuance does not select winners, collect entries, process payments, or provide contest-law compliance.

To download an API log in the website, open the live owner page, enter the Railway admin token, scroll to `Audit Logs`, and choose `DOWNLOAD JSON` beside the report.

Customers can choose `REMOVE FROM THIS PC` in License Center. That deactivates the current machine receipt through the API and then removes the saved key and receipt locally. `CLEAR LOCAL COPY ONLY` is an offline fallback and does not notify the API. The ranks run from `$5 Starter` through `$20,000+ Pro Baseline`; old `plus`, `pro`, and `signature` keys remain compatible. The admin token is masked, sent only in the `X-License-Admin-Token` header, and never written to settings, receipts, logs, or GitHub.

Rank names describe software and service packages. The app does not claim HIPAA certification, legal approval, guaranteed protection, or completed professional review.

## Repo safety notes

This repo intentionally leaves out machine-bound or private runtime data such as:

- local audit logs
- DPAPI-bound audit keys
- active settings files
- temporary files
- generated build output
- packaged installer folders

Use `settings.example.json` as the template for fresh installs or for documenting config shape.

## Good files to share

- `.py` source files
- `.bat` launchers
- `README.txt`
- `README.md`
- installer source files like `.spec` and `EasyLockerSetup.cs`
- `usb_locker_api/`

## Before pushing to GitHub

1. Double-check that no live keys, vault files, or logs were moved into the folder manually.
2. Make sure `settings.json` stays ignored and only `settings.example.json` is shared.
3. Review staged files before each commit.
4. Push the full app repo and the standalone API repo separately if you want cleaner project pages.
