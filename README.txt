USB File Locker

This app locks files with:
- your master USB key file
- an optional extra PIN, if you type one
- portable AES-256-GCM authenticated encryption

Saved settings, the last loaded key path, the audit chain, and the personal vault
live in `%LOCALAPPDATA%\USBFileLocker` so app updates do not reset them when you
replace the app folder.

New locks work on another Windows PC when you use the same master USB key and
the exact same optional PIN.

First run:
- Double-click any "Run ... .bat" launcher.
- The launcher checks Python and installs cryptography 49.0.0 if it is missing.
- The first dependency setup needs an internet connection. Later starts reuse it.

Updates:
- Version 2026.07.15.1 adds BACKUP VERIFICATION CENTER with 12 fixed plans,
  60 restore-order steps, 9 categories, and 12 coarse local checks totaling
  100 readiness points. It can create an app-data backup and verify a selected
  recognized backup folder without retaining its path.
- Customers can choose 5 fixed restore-time objectives, a 1-5 copy target, and
  7, 14, 30, 60, or 90-day reviews. Hash-chained checkpoints compare score
  changes plus gained or lost fixed check IDs without storing private details.
- API 0.31.0 adds public BACKUP VERIFICATION pages with current-tab-only
  progress, fixed restore-order copy, print, and safe JSON export. It receives
  no customer backup, path, file, progress, checkpoint, or account data.
- APPS HUB now has 24 tools, LOCAL CONTROL has 17 approved apps, and owner
  readiness covers 12 public surfaces. The signed customer package has 44
  transparent files and still excludes keys, settings, logs, and locked data.
- Version 2026.07.14.7 adds RECOVERY DRILL CENTER with 16 fixed drills and 80
  unique steps across backup, continuity, evidence, recovery, and security.
  Ten coarse local checks total 100 readiness points. Customers can use a
  random drill, mark progress, schedule a 7, 14, 30, 60, or 90-day local
  review, see the next due date, open trusted tools, and export reviewed safe
  reports. Coarse complete or partial history uses a local hash chain.
- API 0.30.0 adds public RECOVERY DRILLS pages with current-tab-only progress,
  fixed-step copy, print, and safe JSON export. It accepts no files or free
  text and collects no customer drill history. APPS HUB now has 20 tools,
  LOCAL CONTROL has 16 approved apps, and owner readiness covers 11 public
  surfaces using aggregate status only.
- Recovery drill reports and history exclude paths, filenames, keys, PINs,
  file contents, identities, machine details, receipts, and free-form notes.
  Ransomware practice is tabletop guidance only and never runs malware or
  destructive file-encryption simulations.
- Version 2026.07.14.6 adds INCIDENT RESPONSE CENTER with 8 coarse local checks
  totaling 100 readiness points and 12 fixed playbooks containing 72 safe steps.
  It covers Defender alerts, account theft, a lost master USB, unlock failure,
  unknown PC behavior, update integrity, device loss, phishing, ransomware
  warnings, exposed secrets, browser changes, and backup failures. It can open
  Windows Security and trusted VaultLink tools, but never quarantines, deletes,
  uploads, scans, or remotely controls the PC.
- API 0.29.0 adds public INCIDENT RESPONSE pages with current-tab-only progress,
  copy-next-step, print, safe JSON export, no free text or file uploads, and no
  customer records. APPS HUB now has 16
  tools, LOCAL CONTROL has 15 approved apps, and owner readiness covers 10 public
  surfaces using aggregate status only.
- Incident exports exclude license proof, identities, passwords, PINs, USB
  secrets, paths, filenames, screenshots, process lists, and file contents.
- Version 2026.07.14.5 adds DIAGNOSTICS CENTER with 18 explainable read-only
  checks totaling 100 points. It covers runtime, encryption dependencies, app
  files, storage, settings, audit integrity, Defender and signatures, USB/key
  readiness, Local Control PIN, license, API, clock, signed update, recovery
  test, and app-data backup. It has category and attention filters plus reviewed
  safe JSON and copied-summary exports.
- API 0.28.0 adds a public DIAGNOSTICS browser app with 8 fixed problem
  categories and 40 concrete steps. Progress stays only in the current tab and
  is never uploaded or saved in browser storage. It accepts no free text or
  files. APPS HUB now has 15 tools and LOCAL CONTROL has 14 approved apps.
- Diagnostic exports exclude keys, receipts, identities, paths, PINs, USB
  secrets, filenames, vault data, file contents, and raw exception details.
- Version 2026.07.14.4 adds TRUST & RECOVERY CENTER, an explainable local
  100-point report for Defender, audit integrity, USB/key readiness, the separate
  Local Control PIN, license state, signed updates, public API trust, recovery
  tests, and app-data backups. Its safe JSON export excludes license keys,
  receipts, identities, paths, PINs, USB secrets, filenames, and file contents.
- API 0.27.0 adds public TRUST CENTER and owner-only TRUST OPERATIONS pages for
  scored service, release, storage, encryption, audit, recovery, and privacy
  checks. Public output has no customer records; owner output is aggregate-only.
- LOCAL CONTROL CENTER now has 13 approved apps, category filters, uptime and
  session metrics, per-app success/failure totals, stronger browser headers, and
  a CSRF-protected privacy-safe JSON report. APPS HUB now has 12 compact tools.
- Version 2026.07.14.3 expands LOCAL CONTROL CENTER into a same-PC dashboard
  for 12 approved customer apps. It groups tools by task, checks whether each
  app is available, shows coarse license/update/service/session status, supports
  explicit session extension and desktop session lock, and keeps at most 20
  privacy-safe launch entries in memory. Removing or changing the USB key locks
  browser control automatically. The history disappears when the server stops.
- The local dashboard still binds only to 127.0.0.1. It cannot choose files,
  capture encryption PINs, unlock data, accept remote connections, or execute
  arbitrary commands. Status and history exclude keys, receipts, identities,
  paths, PINs, filenames, and file contents.
- Version 2026.07.14.2 adds CUSTOMER SUCCESS tools: a six-factor workspace
  score, 30-day plan, benefit map, action filters, tool search, safe support
  pack, and offline recovery-card export. The owner console adds an aggregate
  experience score, customer journey, renewal buckets, rank percentages,
  surface readiness, and journey CSV export.
- Version 2026.07.14.2 also adds LOCAL CONTROL CENTER. It runs only on
  127.0.0.1 on the same PC, requires the selected USB key plus a separate
  Windows-protected scrypt control PIN, rate-limits failed attempts, uses CSRF
  protection, and locks the session after 15 minutes. It launches only eight
  approved desktop apps. It cannot accept remote connections, upload secrets,
  execute arbitrary commands, or lock and unlock files inside the browser.
- Version 2026.07.14.1 is the CUSTOMER WORKSPACE update. It combines license
  health, anonymous seats, signed release status, a nine-item action plan,
  unlocked rank tools, milestones, upgrade options, customer links, and a
  privacy-safe JSON export. The owner gets an aggregate CUSTOMER EXPERIENCE
  console for rank coverage, support, service, release adoption, public pages,
  shop readiness, and storage health. It does not return customer identity,
  license proof, machine identity, receipts, paths, PINs, USB secrets, or file
  contents.
- Version 2026.07.13.5 lets OWNER UPDATE LAB run the exact verified candidate
  privately without publishing or replacing the stable app. OWNER LAB mode is
  visibly marked and cannot install updates or change file associations. It uses
  normal Windows user data so real license, USB, lock, and unlock flows can be
  tested.
- Version 2026.07.13.4 adds a local aggregate health baseline, automatic drift
  warnings, key-folder coverage, attention-only filtering, and privacy-safe
  copied summaries to VAULT HEALTH CENTER. Baselines and summaries exclude
  names, paths, key IDs, secrets, PINs, licenses, and contents. Signed updates
  preserve the baseline with other LocalAppData.
- Version 2026.07.13.3 adds VAULT HEALTH CENTER for read-only locked-file
  structure checks, legacy review, recovery status, multi-key coverage, safe
  cancellation, and aggregate snapshot comparison. It also adds signed release
  details, SHA-256 copy,
  verification receipts, local readiness, verified download-only mode, anonymous
  update activity, rollback-backup access, and app-data backup to UPDATE CENTER.
  The private OWNER UPDATE LAB adds a 15-check preflight, package inspector,
  report export, hash-chained history, and owner shortcuts. Owner tools remain
  outside customer ZIPs. Keys, licenses, settings, vault data, audit logs, and
  locked files remain preserved by signed updates.
- Version 2026.07.13.2 adds a private local OWNER UPDATE LAB. It tests the app,
  API, signature, ZIP hash, package contents, and Defender scans before publish.
  Publishing repeats the checks, sends the exact tested files through the pinned
  GitHub repositories, waits for Railway, and verifies the live download hash.
  Test and publish require the registered removable owner USB and the
  Windows-protected signing key. The lab is not included in customer update ZIPs.
  The API now verifies the Ed25519 signature, package size, and SHA-256 hash too.
  Owner tools also include a 15-check preflight, package viewer, hash copy,
  privacy-safe report export, hash-chained release history, candidate-folder
  access, and shortcuts to the live owner pages and pinned GitHub repositories.
- Version 2026.07.13.1 adds direct desktop links to the online UPDATE CENTER
  and RECOVERY READINESS app, plus a two-row toolbar that keeps every main
  action visible. The readiness self-check stores nothing and marks missing
  backup, USB-key test, or disposable-file round trip as blockers.
- Version 2026.07.12.9 adds a standalone CUSTOMER HUB for every rank, earlier
  owner announcements, draft Terms and Privacy pages, and temporary LIMITED or
  BLOCK owner controls. LIMITED never remotely disables unlock or recovery.
- Version 2026.07.12.8 adds CUSTOMER CENTER with privacy-safe license, seat,
  version, service, sync, owner-message, and automatic-update status. It never
  displays the license key, receipt, machine id, files, or paths.
- Version 2026.07.12.7 adds a local AUTO-INSTALL VERIFIED UPDATES option.
  It installs only after the signed manifest and package hash verify, preserves
  LocalAppData, and remains disabled inside Git working folders.
- CUSTOMER STATUS opens a public page with service and signed-release details.
- Version 2026.07.12.6 adds automatic on-screen owner announcements, service
  notices, and owner API activity visibility. Each notice appears once per PC.
- It includes the 2026.07.12.5 WinError 183 temporary extraction-folder fix.
- UPDATE CENTER checks the API at startup when its daily check is due.
- LICENSE HEARTBEAT checks the API about every 60 seconds and before a premium
  action when the saved decision is stale. Revoked, expired, reset, removed-device,
  and deactivated receipts turn premium controls off without opening License Center.
- License Center shows API version, last decision ID, device-seat usage, sync timing,
  and signed desktop release status returned by the API.
- Every installed build with Update Center reads the same published API release.
- Every release manifest must verify with the embedded Ed25519 public key.
- The ZIP must match the signed SHA-256 hash before installation.
- The app asks before installing and backs up files it replaces.
- Keys, licenses, vault data, settings, and logs in LocalAppData are preserved.

Important:
- Keep the master USB key private.
- Make a backup of the master USB key.
- If you lose the key, locked files cannot be recovered.
- If you use the optional PIN and forget it, those locked files cannot be recovered.
- The app keeps original files by default. It creates a new .locked file beside them.

Use:
1. Double-click "Run USB File Locker.bat".
2. Click CREATE MASTER USB KEY and save it on your USB drive.
3. RECENT KEYS remembers your last USB key paths so you can reload them faster.
4. OPEN DATA FOLDER jumps to `%LOCALAPPDATA%\USBFileLocker`.
5. BACK UP APP DATA copies settings, the audit chain, and the personal vault into a timestamped backup folder without including USB key files.
6. RESTORE APP DATA loads one of those backup folders back into `%LOCALAPPDATA%\USBFileLocker` and makes a safety snapshot first.
7. REMOVE SELECTED takes highlighted files or folders out of the queue without clearing everything.
8. OPEN SELECTED and OPEN FOLDER help you jump to what is already queued.
9. REMOVE MISSING clears dead paths from the queue. SORT LIST cleans the queue order.
10. SAVE LIST and LOAD LIST let you keep big file queues in text files.
11. Click ADD FILES for files or ADD FOLDER for a complete folder.
12. Or click SCAN PERSONAL FILES to search Desktop, Documents, and Downloads
   for personal-looking filenames.
13. ADD PERM UNLOCK ITEMS pulls files back in from the desktop PERM UNLOCK folder
   so you can edit them and lock them again faster.
14. PANIC LOCK NOW instantly unloads the USB key, clears the PIN box, and closes
   extra windows.
15. VERIFY OWNER USB shows whether the currently loaded key matches the registered
   owner USB rule on this PC.
16. Click LOCK COPY.
17. To unlock, load the same USB key, add .locked files, and click UNLOCK HERE.
18. If you cannot find the locked files, click FIND LOCKED.
19. UNLOCK HERE saves beside the .locked file. UNLOCK TO FOLDER asks where to save.
20. For all files, UNLOCK HERE opens a temporary unlocked copy and deletes that
   unlocked copy afterward. The .locked file stays.
21. Text-like files delete after you close Notepad. Other files show a cleanup
   window with DELETE NOW and an auto-delete timer.
22. Use UNLOCK TO FOLDER if you want to keep an unlocked copy.
23. Large lock and unlock batches run in the background so the window stays responsive.
24. CANCEL AFTER CURRENT stops before the next selected item.

Double-click unlock:
- Double-click a .locked file to open a small unlock prompt.
- Choose your master USB key file.
- Type the optional PIN if you used one when locking.
- Pick an output folder or leave it blank to unlock beside the .locked file.
- If double-click stops working, open the main app and click REGISTER .LOCKED.

TXT files:
- A normal file like passcode.txt is not locked.
- Its locked version is passcode.txt.locked.
- Unlock passcode.txt.locked to view a temporary restored passcode.txt.
- If you select passcode.txt and passcode.txt.locked is beside it, the app will
  automatically use the .locked version.

Safe scan:
- SCAN PERSONAL FILES checks filenames only.
- It does not scrape browsers, tokens, cookies, app passwords, or hidden stores.
- It adds matching files to the lock list so you can choose what to lock.

Optional:
- Type an EXTRA PIN before locking if you want both USB key + PIN protection.
- Leave EXTRA PIN blank if you want USB key only.
- The PIN is exact and case-sensitive.
- A non-empty PIN must be entered twice before new data is locked.
- SHOW PIN lets you check what you typed.
- LOCK A TEXT NOTE lets you type text and save it as a locked note.
- PERSONAL VAULT lets you lock personal stuff like passcodes, recovery codes,
  account names, email notes, phone/address info, and private notes.

Personal Vault:
- Load your USB key first.
- Type the same optional PIN you want to use for the vault.
- Click PERSONAL VAULT.
- Add an item, pick its type, and click SAVE ITEM.
- IMPORT TEXT FILE loads a chosen text file into the editor. Click SAVE ITEM
  after checking it.
- COPY SECRET copies the selected secret to your clipboard.
- DELETE removes the selected vault item.
- The vault is saved as personal_vault.usblock in this folder.
- Newly saved vaults use the portable USB-key and PIN encryption format.

Folders:
- ADD FOLDER can lock a complete folder, including nested and empty folders.
- Folder links and junctions are rejected so the app cannot silently archive data
  outside the selected folder.
- A locked folder ends with .folder.locked.
- Unlocking restores a new folder and never overwrites an existing folder.

Old locks:
- USBLOCK1 files made by an older version are tied to the Windows account that
  created them, even with the correct USB key and PIN.
- On the original Windows account, select the old files and click UPGRADE OLD LOCKS.
- The upgrade creates a verified portable copy and keeps the old locked file.
- Copy the new .portable.locked file to the other PC.
- CHECK LOCK FORMAT identifies portable and old Windows-bound locks.

Recovery Center:
- RUN KEY + PIN RECOVERY TEST creates, locks, unlocks, verifies, and deletes
  harmless random test data.
- VERIFY SELECTED LOCKS checks the key, PIN, authentication tag, archive safety,
  and expected size without leaving a permanent unlocked copy.
- BACK UP LOADED USB KEY makes a second key file and verifies it byte-for-byte.
- COMPARE A BACKUP KEY confirms whether another key can unlock the same data.
- Keep backup keys on separate private USB drives.

Log:
- Actions are saved to locker_log.jsonl.

Companion apps:
- Run Privacy Safety Hub.bat
  Opens the launcher dashboard for the toolkit.
- Run Locked File Browser.bat
  Finds .locked files fast and opens the unlock prompt for them.
- Run Quick Lock Note.bat
  Lets you type or paste text and save it as a locked note quickly.
- Run Key Inspector.bat
  Reads a master USB key and checks whether it matches the owner USB rule.
- Run PERM UNLOCK Workbench.bat
  Shows what is in the PERM UNLOCK folder and relocks edited items faster.
- Run Personal Vault Pad.bat
  Opens the personal vault in a simpler note-style helper app.
- Run Audit Log Viewer.bat
  Opens the audit chain, uploads privacy-safe reports, downloads a signed copy,
  and shows the API breach summary and storage lifetime. AUTO-UPLOAD EVERY 15 MIN
  is opt-in and skips uploads when the meaningful snapshot has not changed.
- Run License Issuer.bat
  Issues all seven API license ranks with enforced device limits and optional private
  owner notes. KEYS + NOTES WEBSITE shows API dashboard totals, anonymous active-device
  counts, per-license anonymous device lists, one-device removal, encrypted-at-rest
  keys and notes, seat resets, revoke, and restore controls. It auto-refreshes every
  30 seconds after the owner connects.
  REVOKE LATEST removes the newest key. API LOGS lists stored breach reports and
  downloads a selected report. The Railway admin token is masked and never saved.
- The API /shop page shows all seven ranks. A BUY button appears only when the owner
  configures an allowlisted provider-hosted HTTPS checkout link. VaultLink never
  collects card numbers. The owner confirms payment separately and then issues the
  matching license; checkout does not automatically create a key.
- OWNER NEWS shows active read-only messages published from the owner website for
  your license rank. Messages can be scheduled or expired by the owner, and they
  cannot run commands, read files, or change settings. SHOP opens the public shop
  without putting a license key or activation receipt in the browser URL.

License Center:
- REMOVE FROM THIS PC deactivates that machine receipt through the API and clears
  the saved local key and receipt after the server confirms it.
- CLEAR LOCAL COPY ONLY is an offline fallback and does not notify the API.
- BUG CENTER sends only the category, subject, description, and optional steps that
  the customer types. It never attaches files or local logs automatically. Customers
  can use CHECK OWNER REPLIES from the same licensed PC.
- On the owner website, BUG INBOX lets the owner acknowledge, mark in progress,
  resolve, close, reply, save a private note, or permanently delete a report.
- To download API logs, open the owner website, connect with the Railway admin token,
  scroll to AUDIT LOGS, and click DOWNLOAD JSON. API LOGS in License Issuer also works.
- Run Text Log Processor.bat
  Pastes or loads table-style text logs, counts actions, spots failures and duplicate sequence numbers, and exports a cleaner report.
- Run Global Breach Guard.bat
  Starts a global topmost breach watcher that checks the signed audit trail every few seconds and throws an on-screen alert for high-risk or critical signals.

Locked File Browser:
- Double-click "Run Locked File Browser.bat".
- FAST SCAN checks common folders quickly. HOME SCAN goes wider.
- Double-click a result or use UNLOCK SELECTED to open the unlock prompt.
- OPEN MAIN LOCKER jumps back into the full locker app.
