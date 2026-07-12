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
- UPDATE CENTER checks the API at startup when its daily check is due.
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
  counts, encrypted-at-rest keys and notes, seat resets, revoke, and restore controls.
  REVOKE LATEST removes the newest key. API LOGS lists stored breach reports and
  downloads a selected report. The Railway admin token is masked and never saved.

License Center:
- REMOVE FROM THIS PC deactivates that machine receipt through the API and clears
  the saved local key and receipt after the server confirms it.
- CLEAR LOCAL COPY ONLY is an offline fallback and does not notify the API.
- Run Text Log Processor.bat
  Pastes or loads table-style text logs, counts actions, spots failures and duplicate sequence numbers, and exports a cleaner report.
- Run Global Breach Guard.bat
  Starts a global topmost breach watcher that checks the signed audit trail every few seconds and throws an on-screen alert for high-risk or critical signals.

Locked File Browser:
- Double-click "Run Locked File Browser.bat".
- FAST SCAN checks common folders quickly. HOME SCAN goes wider.
- Double-click a result or use UNLOCK SELECTED to open the unlock prompt.
- OPEN MAIN LOCKER jumps back into the full locker app.
