# USB File Locker App

USB File Locker App is a Windows desktop toolkit for locking files and folders with a USB key, keeping a personal vault, reviewing privacy-safe audit logs, and watching for suspicious access patterns.

The Audit Log Viewer can upload its approved privacy-safe report fields to the licensed Railway API and immediately download a signed JSON copy. Its explicit `AUTO-UPLOAD EVERY 15 MIN` option sends a new snapshot only when meaningful audit or Defender state changes. The API stores a breach summary with each report. Owners can open `API LOGS` in the License Issuer to list and download stored reports later. The server never receives raw files, file contents, USB secrets, passwords, PINs, client names, or full paths.

The main app's `BUG CENTER` lets a customer explicitly send a category, subject, description, and optional reproduction steps to the owner. No files or local logs are attached automatically. Ticket text is encrypted at rest; the server stores an anonymous machine hash instead of a PC name or raw machine id. Customers can check owner replies from the same licensed PC. The owner can acknowledge, mark in progress, resolve, close, reply, keep a private note, or permanently delete a ticket from the owner website.

The API also provides a public `/shop` page for all seven ranks. Buy buttons appear only for allowlisted provider-hosted HTTPS checkout links, so VaultLink never collects card numbers. A missing or invalid checkout link stays visibly unavailable. Payment confirmation and license issuance remain separate owner actions; this release does not claim automatic fulfillment.

`OWNER NEWS` opens rank-targeted announcements published from the owner website. New messages and non-normal service notices also appear automatically on screen once per PC after a successful license sync. These messages are read-only text, require an active license, respect scheduled start and expiration times, and cannot execute commands, access files, or change settings. Only anonymous announcement IDs are saved to prevent repeat popups. `SHOP` opens the public shop without placing the license key or activation receipt in the URL.

## First run

Double-click any `Run ... .bat` launcher. `Ensure Dependencies.cmd` checks for Python 3.9 or newer and imports the pinned `cryptography` package. If that package is missing, the launcher installs it from `requirements.txt`, verifies the import, and then opens the selected app. The first setup needs an internet connection; later starts do not reinstall it.

The app checks the API at startup when its daily update check is due. License state has a separate automatic API heartbeat: it checks about every 60 seconds, follows the server's bounded refresh policy, and re-checks stale state before a premium action. Revoked, expired, reset, removed-device, or deactivated receipts disable premium controls without requiring License Center. A temporary outage keeps a still-valid cached receipt usable within the existing offline grace period. Update Center verifies an Ed25519 manifest signature and SHA-256 package hash, clearly shows the current release, backs up replaced app files, and preserves everything in `%LOCALAPPDATA%\USBFileLocker`. `AUTO-INSTALL VERIFIED UPDATES` is a visible local opt-in; when enabled, a verified update downloads, verifies again, closes the app, installs, and restarts without an extra prompt. Automatic installation remains disabled inside Git working folders; use `git pull` there.

Release `2026.07.17.9` adds privacy-safe prior receipt comparison to Download Verification Center. After checking a file, a customer can explicitly choose one earlier VaultLink JSON receipt and compare its calculated SHA-256, coarse size band, extension, signature state, one-way signer fingerprint, Defender state, detected type, extension/header state, PE architecture, fixed warning IDs, and aggregate ZIP summary.

Receipt import is local-only, rejects links and non-JSON files, requires strict UTF-8 JSON with the supported schema, and is capped at 256 KB. Unknown fields are discarded, arbitrary imported text is never displayed or exported, and neither receipt is uploaded automatically. Comparison exports contain only hashes and fixed change or warning IDs. The result distinguishes different bytes, identical bytes with changed signals, and an exact fixed-field match. A prior receipt can be edited and is not a signed security certificate; even an exact match does not prove a file is safe.

API `0.48.0` publishes the comparison capability and accepts only two additional fixed audit action names for compare and export success or failure. The API still receives no receipt, selected file, hash, signer information, path, filename, or comparison output automatically.

Release `2026.07.17.8` expands Download Verification Center with bounded file-structure review. It detects Windows PE, shortcuts, ZIP-based formats, PDF, PNG, JPEG, GIF, 7z, RAR, GZIP, ELF, OLE compound files, and plain text from fixed header signatures. It compares mapped extensions to detected headers, reads PE architecture without loading the executable, and flags executable/script extensions, misleading document-plus-executable double extensions, malformed PE headers, Windows shortcuts, and macro-enabled Office extensions.

ZIP review reads only the central directory and never extracts or opens an entry. It reviews at most 10,000 entries and reports aggregate counts for absolute or parent-traversal paths, links, encrypted entries, executable/script extensions, nested archives, Office macro project names, extreme compression ratios, declared expansion over 50 GB, and truncated review. Privacy-safe receipts contain only fixed warning IDs and counts, never archive entry names.

API `0.47.0` updates Download Verification Center metadata for structural and archive review. The checks remain local, read-only warning signals and are not malware detection or a guarantee that a file is safe.

Release `2026.07.17.7` adds Download Verification Center. A customer explicitly selects one ordinary file up to 8 GB, calculates its SHA-256 in bounded chunks, optionally compares a 64-character expected SHA-256, and asks Windows to inspect its Authenticode signature. The app rejects links and detects a file that changes during hashing or signature inspection.

Microsoft Defender scanning is a separate explicit button. It runs a custom file scan through `MpCmdRun.exe` with remediation disabled, no exclusions, no shell command, and no automatic execution of the selected file. The GUI and privacy-safe JSON receipt clearly state that a matching hash, valid signature, or no-threat scan does not guarantee a file is safe. Receipts include the calculated hash, coarse size band, extension, comparison state, signature state, signer subject, and Defender state while excluding the filename, path, Windows username, file contents, and raw Defender output.

API `0.46.0` publishes Download Verification Center in product and companion metadata and recognizes only seven fixed audit action names. The API receives no selected file, filename, path, expected hash, calculated hash, signature details, Defender output, or receipt automatically.

Release `2026.07.17.6` adds Support Redactor, a practical local customer tool for cleaning copied error and log text before sharing it. It recognizes VaultLink license and receipt tokens, authentication tokens, labeled passwords and PINs, emails, user-home paths, key filenames, UUIDs, machine identifiers, IPv4 and IPv6 addresses, MAC addresses, phone numbers, US SSNs, valid payment-card numbers, and secret-bearing URL queries while preserving ordinary error context and line structure.

Customers can paste text, open an explicit text-style file up to 5 MB, preview category counts, copy the reviewed result, or save a new redacted text file. Nothing is uploaded automatically, original files are never changed, and audit records contain only fixed action names with success or failure. The app clearly warns that automated redaction cannot guarantee every secret is found. Support Redactor is available from the main customer tools, Customer Hub, Apps Hub, same-PC Local Control, and `Run Support Redactor.bat`.

API `0.45.0` publishes Support Redactor in product and companion metadata and recognizes only its fixed privacy-safe action names in uploaded audit reports. It receives no pasted text, source file, output file, filename, path, redaction preview, category count, or detected value.

Release `2026.07.17.5` expands the Recovery Decision Wizard to ten situations, thirty fixed yes-or-no decision points, forty reviewed outcomes, and 160 ordered action steps. New paths cover failed backups, suspicious messages and phishing, and bounded low-storage cleanup. Choices and decision history stay only in the current browser tab.

The wizard accepts no free-form description, license key, identity, machine identity, file, path, filename, PIN, USB secret, or local result. It cannot inspect, scan, lock, unlock, install, delete, quarantine, or control a customer PC. Customer Hub links directly to both the wizard and Customer Answers without placing license proof in either URL.

API `0.44.0` serves the expanded fixed decision catalog and continues serving Customer Answers and customer workspace schema 4. It still activates no seat, controls no customer PC, and returns no license proof, customer identity, owner notes, receipts, machine identity, paths, PINs, USB secrets, payment data, or file contents.

Owner Update Lab can set the minimum-supported floor to the current candidate with `REQUIRE THIS RELEASE`. A desktop below that signed floor automatically stages the update after any active local file task finishes, even when optional automatic updates are off. The update still requires a valid Ed25519 manifest signature and matching SHA-256 package hash. Failure never disables unlock, recovery, exports, keys, app data, or existing `.locked` files.

Release `2026.07.16.5` expands Owner Maintenance Operations with six non-overlapping approval gates, a failed-check-only decision queue, five review lanes, and a current-tab owner review session. The session can focus the next action, mark a visible lane reviewed, clear local marks, and export a privacy-safe fixed-field handoff. Review marks do not resolve actions or prove remediation.

The admin-token-protected cockpit keeps its exact forty checks and eight categories plus daily briefing, severity, domain scores, ten-metric change watch, four fixed review windows, owner shortcuts, auto-refresh, print, calendar, and privacy-safe text, JSON, CSV, handoff, and SHA-256 receipt exports. No review mark, lane, baseline, planner choice, filter, or search state is uploaded. Exports exclude license keys, license IDs, customer identity, owner notes, receipts, machine identifiers, report contents, files, paths, PINs, USB secrets, and customer maintenance history. API `0.39.0` provides the schema-three protected report and remains read-only toward customer PCs.

Release `2026.07.16.2` expands Security Maintenance Center with a readiness dashboard, priority queue, and fixed attention, 7-day, 30-day, and 90-day planning windows. Eight category and six routine summaries show a clearly labeled schedule-coverage score. That score measures reminder coverage only; it is not an antivirus, backup, key, recovery, compliance, or security-health result.

Customers can save and compare coarse local snapshots protected by an exact thirteen-field SHA-256 hash chain capped at 200 records and 1 MiB. Snapshots contain only coarse fixed counts, UTC time, anonymous event IDs, and integrity hashes. A verified non-destructive archive export combines the fixed-field event and snapshot chains without resetting or deleting active history. API `0.36.0` adds four fixed cadence horizons, category and routine coverage bars, priority review, and a sixteen-field browser receipt. Browser state still disappears on reload, and no progress, snapshots, scores, history, files, paths, or local results are sent to the API.

Release `2026.07.16.1` adds Security Maintenance Center. It provides thirty-two fixed defensive tasks across Windows Security, signed software, key custody, locked data, app-data backup, recovery practice, audit and privacy, and license and service. Every category contains four tasks. Task-specific cadence is fixed at 7, 14, 30, 60, or 90 days, and six routines cover weekly security, monthly core, key custody, backup and recovery, privacy and evidence, and full maintenance.

Customers can filter by category, routine, and state; record complete or reopen events; open only a hardcoded trusted Windows or VaultLink tool; copy a safe summary; and export reviewed JSON, text, calendar, or verified history. The append-only history is capped at 500 records and 2 MiB and uses an exact ten-field SHA-256 hash chain. It contains only fixed task IDs, fixed cadence, completion or reopen state, UTC time, anonymous event ID, and integrity hashes. It contains no names, contacts, keys, PINs, paths, filenames, file contents, scan results, customer records, screenshots, process lists, or free-form notes.

API `0.35.0` adds `/maintenance` and `/api/v1/maintenance-guide`. Browser review stays only in the current tab, and the API accepts no progress, local result, completion history, reminder, maintenance command, identity, file, or path. A completion record is a reminder, not proof that Defender, Windows, a key, a backup, an update, or recovery is healthy. Apps Hub now contains thirty-two tools, same-PC Local Control launches twenty-one approved apps, the owner Customer Experience Console covers sixteen aggregate public surfaces, and the signed customer package contains fifty-two transparent files.

Release `2026.07.15.4` adds Storage & Retention Center. It maps eight fixed VaultLink storage areas and verifies ten explainable controls worth 100 points. The only cleanup target is the exact `%LOCALAPPDATA%\USBFileLocker\temp` workspace. Preview is bounded to 5,000 entries, links and junctions block cleanup, and age plus directory boundaries are revalidated immediately before deletion. Cleanup requires both a visible yes/no warning and exact `CLEAN TEMP` text.

The center never cleans keys, vault data, audit evidence, recovery histories, privacy baselines, settings, licenses, owner controls, update rollback, owner-lab records, `.locked` files, backups, Downloads, Documents, USB drives, or arbitrary folders. Cleanup is ordinary deletion, not guaranteed secure erasure. Exact-schema hash-chained receipts contain only fixed IDs, coarse bands, counts, status, UTC time, an anonymous event ID, and integrity hashes. API `0.34.0` adds `/retention` and `/api/v1/retention-guide`; browser review stays only in the current tab and the API accepts no inventory, progress, cleanup commands, local results, files, or paths. Apps Hub now contains thirty tools, same-PC Local Control launches twenty approved apps, the owner Customer Experience Console covers fifteen aggregate public surfaces, and the signed customer package contains fifty transparent files.

Release `2026.07.15.3` adds Local Data Control Center. It maps fourteen fixed VaultLink data classes across five scopes and runs eleven explainable local checks worth 100 points. The center reads only coarse metadata from exact known locations inside `%LOCALAPPDATA%\USBFileLocker`; it does not search Downloads, Documents, USB drives, locked-container locations, arbitrary backup folders, browser data, or process lists.

Customers can filter the map, copy a reviewed summary, export safe JSON or text, open the known app-data folder, and save exact-schema hash-chained privacy receipts. Reports and receipts exclude names, contacts, license proof, keys, PINs, paths, filenames, file contents, screenshots, process lists, and free-form notes. API `0.33.0` adds `/data-control` and `/api/v1/data-map`; review progress exists only in the current browser tab, and the API accepts no inventory, customer progress, contacts, files, paths, or local results. Apps Hub now contains twenty-eight tools, same-PC Local Control launches nineteen approved apps, the owner Customer Experience Console covers fourteen aggregate public surfaces, and the signed customer package contains forty-eight transparent files.

Release `2026.07.15.2` adds Recovery Kit Builder. Five fixed profiles select from ten sections and fifty preparation items across eight categories. Five emergency runbooks contain thirty ordered steps for a replacement PC, lost USB key, unlock problem, suspected malware, or service outage. Ten coarse local checks total 100 readiness points. Customers can save reviewed fixed-ID snapshots, compare progress, choose a 7, 14, 30, 60, or 90-day review interval, export safe JSON or text, create an `.ics` calendar reminder, and copy a fixed runbook or summary.

Recovery Kit snapshots use an exact-schema local hash chain. They contain fixed IDs, coarse scores and totals, interval, UTC time, anonymous event ID, and integrity hashes only. They never contain names, contacts, license proof, receipts, keys, PINs, paths, filenames, file contents, screenshots, process lists, or free-form notes. API `0.32.0` adds `/recovery-kit` and `/api/v1/recovery-kit`; browser progress remains in the current tab and the API receives no customer progress or local results. Apps Hub now contains twenty-six tools, same-PC Local Control launches eighteen approved apps, the owner Customer Experience Console covers thirteen aggregate public surfaces, and the signed customer package contains forty-six transparent files.

Release `2026.07.15.1` adds Backup Verification Center. Twelve fixed plans contain sixty backup and restore steps across keys, locked data, app data, application files, devices, people, business continuity, security, and recovery. Twelve coarse local checks total 100 readiness points. Customers can create an app-data backup, verify a selected recognized backup folder without retaining its path, choose one of five restore-time objectives and a one-to-five copy target, follow the fixed restore order, schedule 7, 14, 30, 60, or 90-day reviews, and export a reviewed privacy-safe report.

Coarse backup checkpoints use a local tamper-evident hash chain and compare score changes plus gained or lost fixed check IDs. They never contain backup paths, filenames, keys, PINs, file contents, customer identity, machine identity, receipts, screenshots, process lists, or free-form notes. API `0.31.0` adds `/backup-verification` and `/api/v1/backup-verification`; browser progress stays only in the current tab and the API receives no customer backup data. Apps Hub now contains twenty-four tools, same-PC Local Control launches seventeen approved apps, and the owner Customer Experience Console sees aggregate readiness for twelve public surfaces.

Release `2026.07.14.7` adds Recovery Drill Center. Sixteen fixed drills contain eighty unique steps across backup, continuity, evidence, recovery, and security. Ten coarse local checks total 100 readiness points. Customers can filter and practice drills, mark the next or every step, choose a random drill, set a 7, 14, 30, 60, or 90-day local review interval, see the next due date, open trusted VaultLink tools and Windows Security, and export reviewed summaries. Coarse complete or partial results use a tamper-evident local hash chain. History never contains paths, filenames, keys, PINs, file contents, customer identity, machine identity, receipts, or free-form notes.

API `0.30.0` adds `/recovery-drills` and `/api/v1/recovery-drills`. The responsive browser workspace provides the same sixteen drills and eighty fixed steps, but keeps progress only in the current tab and does not receive customer drill history. It accepts no free text or files. Apps Hub now contains twenty compact tools, same-PC Local Control launches sixteen approved apps, and the owner Customer Experience Console sees aggregate readiness for eleven public surfaces. Ransomware practice is tabletop guidance only; VaultLink never runs malware, suspicious code, destructive scripts, or file-encryption simulations.

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

The Owner Update Lab also includes a 15-check read-only preflight, signed-package content inspection, SHA-256 copy, privacy-safe JSON report export, hash-chained release history, candidate-folder access, and shortcuts to the live Owner Console, Owner Maintenance Operations, Update Center, and pinned app/API GitHub repositories. Its reports and history exclude USB secrets, key paths, signing keys, passwords, PINs, license keys, customer data, file contents, and LocalAppData paths.

## Main desktop apps

- `usb_file_locker.py` - main locker window
- `customer_hub.py` - privacy-safe customer workspace with account health, action plan, rank tools, and safe export
- `recovery_kit_builder.py` - fixed recovery profiles, emergency runbooks, local readiness checks, hash-chained snapshots, and calendar reminders
- `incident_response_center.py` - fixed incident playbooks, coarse local readiness, trusted tool shortcuts, and reviewed safe export
- `diagnostics_center.py` - eighteen read-only runtime, storage, Defender, audit, USB, service, update, and recovery checks
- `download_verification_center.py` - local SHA-256, expected-hash, Authenticode, and explicit Defender checks for one selected file
- `local_control_center.py` - loopback-only website launcher protected by USB presence and a separate local control PIN
- `security_maintenance_center.py` - fixed defensive tasks, due dates, routines, trusted-tool shortcuts, safe exports, and hash-chained local completion history
- `local_data_control_center.py` - fixed local data map, eleven protection checks, coarse exports, and hash-chained privacy receipts
- `storage_retention_center.py` - fixed storage map, ten controls, exact-temp cleanup, and hash-chained coarse retention receipts
- `trust_recovery_center.py` - scored local trust, signed-update, Defender, audit, backup, and recovery-readiness report
- `privacy_safety_hub.py` - dashboard and safety controls
- `personal_vault_pad.py` - simpler personal vault window
- `audit_log_viewer.py` - signed audit trail viewer
- `license_issuer.py` - owner-only API license issuer; the admin token is masked and never saved
- `global_breach_guard.py` - topmost watcher for repeated risky events
- `support_redactor.py` - locally removes common secrets and personal details from explicitly provided support text
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

Run `Run License Issuer.bat` or open License Center and choose `ISSUER APP`. Enter the Railway `LICENSE_ADMIN_TOKEN`, choose one of the seven visible ranks, set its maximum device count, add an optional private owner note, and issue the key. The API enforces that device limit with anonymous machine hashes. `KEYS + NOTES WEBSITE` opens the owner console, where the same admin token can view dashboard totals, anonymous desktop-version adoption and 24-hour sync freshness, shop readiness, scheduled rank-targeted Owner Announcements, informational service status, the tamper-evident API activity chain, anonymous device seats, encrypted-at-rest keys and notes, revocation controls, the Bug Inbox, privacy-safe audit logs, and time-limited giveaway licenses. `OWNER OPERATIONS` opens the separate forty-check readiness cockpit and privacy-safe runbook. Giveaway issuance does not select winners, collect entries, process payments, or provide contest-law compliance.

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
