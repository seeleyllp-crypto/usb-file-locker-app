# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, security notes, and all seven license ranks
- API-backed licensing with signed keys, machine receipts, automatic client heartbeats, device deactivation, and owner revocation
- Persistent anonymous device-seat enforcement using each license's `max_devices` value
- Per-license anonymous device inventory with throttled last-heartbeat/app-version details and one-device removal without resetting every seat
- An owner-only keys and private notes website at `/owner` with 30-second automatic refresh
- Privacy-safe audit report upload with signed, expiring downloads
- Server-calculated breach summaries plus admin-protected report listing and downloads
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

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

Recommended Railway environment variables:

- `LICENSE_SIGNING_SECRET` = a long random secret used to sign license keys and receipts
- `LICENSE_ADMIN_TOKEN` = a long random admin token used for owner-only license and audit routes
- `LICENSE_STATE_DIR` = persistent folder for revocations, device deactivations, encrypted keys, and private owner notes
- `LICENSE_RECORDS_SECRET` = a separate long secret used to encrypt saved keys and owner notes; retain it across deployments
- `AUDIT_EXPORT_DIR` = optional persistent folder for audit exports; mount a Railway Volume and point this variable at it
- `AUDIT_EXPORT_RETENTION_HOURS` = optional lifetime for stored exports, from 1 to 2160 hours; default 168

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
- `http://127.0.0.1:8000/owner`

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
  - Admin-only license, device-capacity, audit-export, breach-level, storage, and release totals.

Open `/owner` to view the API dashboard, issue keys, enforce device limits, inspect and remove one anonymous device, reset all lost-device seats, copy keys, save private notes, revoke licenses, and restore licenses. Once connected, the page refreshes owner data every 30 seconds. The admin token stays in page memory, is sent only in the `X-License-Admin-Token` header, and is not placed in a URL.

Without `LICENSE_STATE_DIR`, Railway uses local ephemeral storage and a restart can forget revocations and owner records. Mount a Railway Volume and use paths such as `/data/license_state` and `/data/audit_exports`. Keep `LICENSE_RECORDS_SECRET` stable; changing or losing it makes previously encrypted keys and private notes unreadable.

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

Without `AUDIT_EXPORT_DIR`, Railway stores exports on the service's local ephemeral filesystem. Upload, owner listing, and download work, but a restart can remove pending exports. For restart-safe retention, mount a Railway Volume and set `AUDIT_EXPORT_DIR` to that mount, such as `/data/audit_exports`.

## Update endpoints

- `GET /api/v1/updates/windows`
  - Returns the current Ed25519-signed Windows release manifest, compatibility floor, notes, size, and SHA-256 hash.
- `GET /api/v1/updates/windows/download`
  - Returns the exact ZIP package named by the signed manifest.

The desktop app embeds the release public key and will not trust a replacement key from the API. It verifies the manifest signature and package hash before staging an update, asks the user before installation, backs up replaced app files, and leaves LocalAppData untouched. The private release-signing key is DPAPI-protected outside both GitHub repositories.
