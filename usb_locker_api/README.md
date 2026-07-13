# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, security notes, and all seven license ranks
- API-backed licensing with signed keys, machine receipts, automatic client heartbeats, device deactivation, and owner revocation
- Persistent anonymous device-seat enforcement using each license's `max_devices` value
- Per-license anonymous device inventory with throttled last-heartbeat/app-version details and one-device removal without resetting every seat
- An owner-only keys and private notes website at `/owner` with 30-second automatic refresh
- An encrypted customer Bug Inbox with owner status actions, private notes, replies, and deletion
- Rank-targeted, scheduled, read-only Owner Announcements with desktop delivery
- Public informational service status with automatic licensed-desktop notices
- A tamper-evident, hash-chained owner activity ledger with scoped JSON downloads
- Anonymous client release-adoption counts and coarse 24-hour sync freshness
- A public customer status page at `/status` with service and signed-release details
- Owner-issued time-limited promotional giveaway licenses
- Privacy-safe audit report upload with signed, expiring downloads
- Server-calculated breach summaries plus direct admin log downloads on the owner website
- A public seven-rank shop at `/shop` using allowlisted provider-hosted checkout links
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`
- Ordered rank JSON at `/api/v1/ranks`
- Signed Windows update manifest and package delivery

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet
- It does not store PC names or raw machine identifiers in the device-seat ledger
- It does not accept raw files, file contents, full paths, USB secrets, passwords, or PINs in audit exports
- Bug reports never attach local files or logs automatically, and raw machine ids are not stored
- Announcements cannot run commands, access customer files, or change customer settings
- Service status is informational and cannot remotely control or disable customer PCs
- API activity records exclude keys, tokens, notes, messages, customer labels, file data, and full paths
- Client health never exposes PC names or raw machine ids; it reports only anonymous counts, app versions, and coarse freshness
- Giveaway tooling does not select winners, collect entries, process payments, or provide contest-law compliance
- It does not collect card numbers, store payment secrets, or treat a checkout receipt as a license key

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

Recommended Railway environment variables:

- `LICENSE_SIGNING_SECRET` = a long random secret used to sign license keys and receipts
- `LICENSE_ADMIN_TOKEN` = a long random admin token used for owner-only license and audit routes
- `LICENSE_STATE_DIR` = persistent folder for revocations, device deactivations, encrypted keys, private owner notes, and support tickets
- `LICENSE_RECORDS_SECRET` = a separate long secret used to derive separate encryption keys for saved license data and support-ticket text; retain it across deployments
- `AUDIT_EXPORT_DIR` = optional persistent folder for audit exports; mount a Railway Volume and point this variable at it
- `AUDIT_EXPORT_RETENTION_HOURS` = optional lifetime for stored exports, from 1 to 2160 hours; default 168
- `SHOP_CHECKOUT_STARTER_URL`, `SHOP_CHECKOUT_HOME_URL`, `SHOP_CHECKOUT_PERSONAL_PLUS_URL`, `SHOP_CHECKOUT_FAMILY_SAFETY_URL`, `SHOP_CHECKOUT_SMALL_OFFICE_URL`, `SHOP_CHECKOUT_FAMILY_OFFICE_URL`, and `SHOP_CHECKOUT_PRO_BASELINE_URL` = optional provider-hosted HTTPS links for each tier
- `SHOP_CHECKOUT_ALLOWED_HOSTS` = optional comma-separated host allowlist; defaults to `buy.stripe.com,checkout.stripe.com`

Railway will start the service with:

`python main.py`

The seven ranks run from `$5 Starter` through `$20,000+ Pro Baseline`. Legacy `plus`, `pro`, and `signature` issue requests map to matching current ranks so older issuer builds keep working. Rank descriptions do not claim HIPAA certification, legal approval, guaranteed protection, or completed professional review.

## Local run

```powershell
cd C:\path\to\USBFileLockerAPI-Repo
python main.py
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/shop`
- `http://127.0.0.1:8000/owner`

## Shop

- `GET /shop` shows all seven ranks and their cumulative features.
- `GET /api/v1/shop` returns the same catalog plus checkout readiness.
- A tier has a buy button only when its environment variable contains a valid HTTPS URL on the checkout-host allowlist. Missing, insecure, spoofed, credential-bearing, or malformed URLs leave that tier marked `NOT ON SALE YET`.
- Payment happens entirely on the checkout provider's page. VaultLink does not receive or store card numbers.
- License delivery is manual: after independently confirming payment in the provider dashboard, the owner issues the matching license from `/owner`.

Use an adult-owned merchant account and follow the payment provider's age, identity, tax, refund, and business requirements. This release does not include webhook-based payment verification or automatic license fulfillment.

## License endpoints

- `POST /api/v1/licenses/issue`
  - Admin-only. Requires `LICENSE_ADMIN_TOKEN` in the `X-License-Admin-Token` header.
  - The admin token is never accepted inside the JSON body.
- `POST /api/v1/licenses/activate`
  - Exchanges a valid license key for a machine-bound receipt.
- `POST /api/v1/licenses/verify`
  - Verifies a license key and activation receipt for a specific machine.
- `POST /api/v1/licenses/sync`
  - Automatic client heartbeat. Returns the current revocation decision, API version, decision ID, bounded next-check timing, device-seat usage, and signed desktop release status.
- `POST /api/v1/licenses/deactivate`
  - Deactivates one machine receipt so the customer can remove the saved license from that PC.
- `POST /api/v1/licenses/revoke`
  - Admin-only. Revokes the whole key so existing and future checks fail.
- `POST /api/v1/licenses/restore`
  - Admin-only. Restores a revoked key; individually deactivated receipts stay deactivated.
- `POST /api/v1/licenses/note`
  - Admin-only. Updates the private owner note without adding it to the signed customer key.
- `POST /api/v1/licenses/reset-devices`
  - Admin-only. Releases every active seat for one license and requires those PCs to activate again.
- `POST /api/v1/licenses/remove-device`
  - Admin-only. Removes one anonymous device seat. Its receipt fails at the next automatic client sync while other devices keep working.
- `GET /api/v1/admin/licenses`
  - Admin-only inventory for the owner website. Includes anonymous active-device counts; stored keys and notes are encrypted at rest.
- `GET /api/v1/admin/licenses/{license_id}/devices`
  - Admin-only anonymous seat inventory. Returns only a one-way machine hash, status, dates, last successful heartbeat, and app version, never a PC name or raw hardware identity. Last-seen writes are throttled to protect the storage volume.
- `GET /api/v1/admin/dashboard`
  - Admin-only license, device-capacity, audit-export, breach-level, shop-readiness, storage, and release totals.

Open `/owner` to view the API dashboard, issue keys, publish Owner Announcements, enforce device limits, inspect and remove one anonymous device, reset all lost-device seats, copy keys, save private notes, revoke licenses, manage the Bug Inbox, and download privacy-safe audit logs. Once connected, the page refreshes owner data every 30 seconds unless an input is being edited. The admin token stays in page memory, is sent only in the `X-License-Admin-Token` header, and is not placed in a URL.

Without `LICENSE_STATE_DIR`, Railway uses local ephemeral storage and a restart can forget revocations, owner records, and bug reports. Mount a Railway Volume and use paths such as `/data/license_state` and `/data/audit_exports`. Keep `LICENSE_RECORDS_SECRET` stable; changing or losing it makes previously encrypted keys, private notes, and support-ticket text unreadable.

## Support ticket endpoints

- `POST /api/v1/support-tickets`
  - Requires an active machine-bound license. Accepts only the category, subject, description, optional reproduction steps, and app version that the customer explicitly submits.
  - Ticket text is encrypted at rest. No files, logs, PINs, passwords, USB secrets, client names, full paths, PC names, or raw machine ids are attached automatically.
- `POST /api/v1/support-tickets/mine`
  - Returns status and owner replies only for tickets from the same licensed anonymous device.
- `GET /api/v1/admin/support-tickets`
  - Admin-only Bug Inbox listing.
- `POST /api/v1/admin/support-tickets/action`
  - Admin-only status, customer reply, and private owner-note update.
- `POST /api/v1/admin/support-tickets/delete`
  - Admin-only permanent ticket deletion.

The API limits each anonymous licensed device to 10 new support tickets per 24 hours.

## Owner announcement endpoints

- `POST /api/v1/announcements/mine`
  - Requires an active machine-bound license and returns only currently active read-only messages allowed for that rank.
- `GET /api/v1/admin/announcements`
  - Admin-only inventory including active, scheduled, and expired messages.
- `POST /api/v1/admin/announcements/create`
  - Admin-only publishing with severity, minimum rank, optional start time, and optional expiration.
- `POST /api/v1/admin/announcements/delete`
  - Admin-only permanent announcement deletion.

Announcements contain only owner-authored text. They cannot execute code, open files, collect device data, or change app settings. Use `/owner` to publish and remove them without command-line tools.

## Audit export endpoints

- `POST /api/v1/audit-exports`
  - Requires an active machine-bound license with Audit Log Viewer access.
  - Accepts the app's privacy-safe report and strips every field outside the approved schema.
  - Returns a signed, expiring download path.
- `GET /api/v1/audit-exports/{export_id}/download`
  - Downloads the JSON report while the returned bearer token is valid.
  - Send the token in the `Authorization: Bearer ...` header so it is not exposed in the URL.
- `GET /api/v1/admin/audit-exports`
  - Admin-only list of stored report metadata, anonymous machine hashes, and breach levels.
  - Requires `LICENSE_ADMIN_TOKEN` in the `X-License-Admin-Token` header.
- `GET /api/v1/admin/audit-exports/{export_id}/download`
  - Admin-only download of a selected stored privacy-safe report.
  - The admin token is never accepted in the URL.
- `POST /api/v1/admin/audit-exports/download-link`
  - Admin-only exchange for a two-minute, report-scoped browser download link. The temporary signed token is not an admin token and cannot access other owner routes.

To download logs without commands, open `/owner`, connect with the admin token, scroll to **Audit Logs**, and click **DOWNLOAD JSON** beside a report.

Without `AUDIT_EXPORT_DIR`, Railway stores exports on the service's local ephemeral filesystem. Upload, owner listing, and download work, but a restart can remove pending exports. For restart-safe retention, mount a Railway Volume and set `AUDIT_EXPORT_DIR` to that mount, such as `/data/audit_exports`.

## Update endpoints

- `GET /api/v1/updates/windows`
  - Returns the current Ed25519-signed Windows release manifest, compatibility floor, notes, size, and SHA-256 hash.
- `GET /api/v1/updates/windows/download`
  - Returns the exact ZIP package named by the signed manifest.

The desktop app embeds the release public key and will not trust a replacement key from the API. It verifies the manifest signature and package hash before staging an update, asks the user before installation, backs up replaced app files, and leaves LocalAppData untouched. The private release-signing key is DPAPI-protected outside both GitHub repositories.
