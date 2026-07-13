# USB File Locker App

USB File Locker App is a Windows desktop toolkit for locking files and folders with a USB key, keeping a personal vault, reviewing privacy-safe audit logs, and watching for suspicious access patterns.

The Audit Log Viewer can upload its approved privacy-safe report fields to the licensed Railway API and immediately download a signed JSON copy. Its explicit `AUTO-UPLOAD EVERY 15 MIN` option sends a new snapshot only when meaningful audit or Defender state changes. The API stores a breach summary with each report. Owners can open `API LOGS` in the License Issuer to list and download stored reports later. The server never receives raw files, file contents, USB secrets, passwords, PINs, client names, or full paths.

The main app's `BUG CENTER` lets a customer explicitly send a category, subject, description, and optional reproduction steps to the owner. No files or local logs are attached automatically. Ticket text is encrypted at rest; the server stores an anonymous machine hash instead of a PC name or raw machine id. Customers can check owner replies from the same licensed PC. The owner can acknowledge, mark in progress, resolve, close, reply, keep a private note, or permanently delete a ticket from the owner website.

The API also provides a public `/shop` page for all seven ranks. Buy buttons appear only for allowlisted provider-hosted HTTPS checkout links, so VaultLink never collects card numbers. A missing or invalid checkout link stays visibly unavailable. Payment confirmation and license issuance remain separate owner actions; this release does not claim automatic fulfillment.

`OWNER NEWS` opens rank-targeted announcements published from the owner website. New messages and non-normal service notices also appear automatically on screen once per PC after a successful license sync. These messages are read-only text, require an active license, respect scheduled start and expiration times, and cannot execute commands, access files, or change settings. Only anonymous announcement IDs are saved to prevent repeat popups. `SHOP` opens the public shop without placing the license key or activation receipt in the URL.

## First run

Double-click any `Run ... .bat` launcher. `Ensure Dependencies.cmd` checks for Python 3.9 or newer and imports the pinned `cryptography` package. If that package is missing, the launcher installs it from `requirements.txt`, verifies the import, and then opens the selected app. The first setup needs an internet connection; later starts do not reinstall it.

The app checks the API at startup when its daily update check is due. License state has a separate automatic API heartbeat: it checks about every 60 seconds, follows the server's bounded refresh policy, and re-checks stale state before a premium action. Revoked, expired, reset, removed-device, or deactivated receipts disable premium controls without requiring License Center. A temporary outage keeps a still-valid cached receipt usable within the existing offline grace period. Update Center verifies an Ed25519 manifest signature and SHA-256 package hash, clearly shows the current release, backs up replaced app files, and preserves everything in `%LOCALAPPDATA%\USBFileLocker`. `AUTO-INSTALL VERIFIED UPDATES` is a visible local opt-in; when enabled, a verified update downloads, verifies again, closes the app, installs, and restarts without an extra prompt. Automatic installation remains disabled inside Git working folders; use `git pull` there.

Release `2026.07.13.1` adds direct desktop links to the online Update Center and Recovery Readiness app and splits the crowded main toolbar into two fully visible rows. The readiness self-check accepts only seven yes-or-no values, stores nothing, and treats missing backups, an untested master USB, or no disposable-file round trip as hard blockers. The signed update replaces app files only and preserves keys, licenses, settings, vault data, and audit logs in `%LOCALAPPDATA%\USBFileLocker`.

## Main desktop apps

- `usb_file_locker.py` - main locker window
- `customer_hub.py` - privacy-safe self-service status and all-seven-rank customer app
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
