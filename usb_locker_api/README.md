# USB File Locker Railway API

This folder contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, and security notes
- A public catalog and homepage comparison for all seven USB locker ranks
- Signed license keys with device deactivation and owner-controlled revocation
- Persistent anonymous enforcement of each license's maximum device count
- An owner-only keys and private notes website at `/owner`
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`
- Ordered rank JSON at `/api/v1/ranks`
- Licensed privacy-safe audit uploads with signed, expiring JSON downloads
- Server-calculated breach summaries plus admin-protected report listing and downloads
- Signed Windows update manifest and package delivery

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet
- It does not accept raw files, file contents, full paths, USB secrets, passwords, or PINs in audit exports

## Railway setup

1. Push this project to GitHub.
2. In Railway, connect the repo.
3. Set the Railway `Root Directory` to `usb_locker_api`.
4. Deploy.

For restart-safe state, mount a Railway Volume and set `LICENSE_STATE_DIR=/data/license_state` and `AUDIT_EXPORT_DIR=/data/audit_exports`. You can also set `AUDIT_EXPORT_RETENTION_HOURS` from 1 to 2160; the default is 168 hours. Without a Volume, Railway can forget revocations, saved owner records, and pending audit exports when the service restarts.

Set a long `LICENSE_RECORDS_SECRET` and keep it stable across deployments. Saved license keys and private owner notes use authenticated encryption at rest; losing or changing that secret makes those private fields unreadable.

License issuance requires the Railway admin token in the `X-License-Admin-Token` header. The API never accepts that token inside a JSON request body.

The owner website at `/owner` shows license/device/audit/breach totals, issues keys, enforces and resets device seats, lists encrypted keys and notes, updates notes, revokes licenses, and restores licenses. Customer removal uses `POST /api/v1/licenses/deactivate`; owner management uses admin-protected `/api/v1/licenses/revoke`, `/restore`, `/note`, `/reset-devices`, `GET /api/v1/admin/licenses`, and `GET /api/v1/admin/dashboard`.

Owner audit review uses `GET /api/v1/admin/audit-exports` and `GET /api/v1/admin/audit-exports/{export_id}/download`. Both require the admin token in the request header. The License Issuer exposes these routes through its `API LOGS` window without saving the token.

Desktop update checks use `GET /api/v1/updates/windows` and `/api/v1/updates/windows/download`. Clients verify the embedded Ed25519 release key and SHA-256 package hash, require user confirmation before installation, back up replaced files, and preserve LocalAppData.

The seven ranks run from `$5 Starter` through `$20,000+ Pro Baseline`. Legacy `plus`, `pro`, and `signature` issue requests map to matching current ranks so older issuer builds keep working. Rank descriptions do not claim HIPAA certification, legal approval, guaranteed protection, or completed professional review.

Railway will start the service with:

`python main.py`

## Local run

```powershell
cd C:\path\to\USBFileLockerApp\usb_locker_api
python main.py
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/owner`
