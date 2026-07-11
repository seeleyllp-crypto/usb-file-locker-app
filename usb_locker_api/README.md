# USB File Locker Railway API

This folder contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, and security notes
- A public plan catalog for your USB locker pricing tiers
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`
- Licensed privacy-safe audit uploads with signed, expiring JSON downloads

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

For restart-safe audit-export retention, mount a Railway Volume and set `AUDIT_EXPORT_DIR` to its folder, such as `/data/audit_exports`. You can also set `AUDIT_EXPORT_RETENTION_HOURS` from 1 to 168; the default is 24 hours. Without a Volume, immediate upload-and-download still works, but Railway can remove pending exports when the service restarts.

License issuance requires the Railway admin token in the `X-License-Admin-Token` header. The API never accepts that token inside a JSON request body.

Railway will start the service with:

`python main.py`

## Local run

```powershell
cd C:\Users\jonis\OneDrive\Desktop\USBFileLockerApp\usb_locker_api
python main.py
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`
