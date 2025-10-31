# PhishGuard Link Verifier (Chrome MV3)

Intercepts link clicks, asks to verify, calls your backend, and blocks/redirects based on the result.

## Requirements
- Backend: FastAPI running locally
  - Verify endpoint: `POST http://127.0.0.1:8001/verify`
  - JSON body: `{ "url": "<clicked_url>" }`
  - Response: `{"status": "...", "confidence": 0-1, "reason": "..."}`

- Frontend (optional):
  - Runs at `http://127.0.0.1:5173`
  - We open `http://127.0.0.1:5173/verify?url=...` in a background tab after “Verify”
  - Suspicious/low-confidence redirects to `http://127.0.0.1:5173/warning?...`

## Ensure CORS in FastAPI
```python
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)
```

## Run Backend
- `python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8001`

## Install Extension
1. Go to `chrome://extensions` (or `edge://extensions`)
2. Enable “Developer mode”
3. Click “Load unpacked”
4. Select the `phishguard_extension/` folder

## How it works
- On any link click:
  - Navigation is paused.
  - A top bar appears: “PhishGuard detected a link … Verify | Ignore”
  - If ignored for 6s, we treat as Ignore and proceed to the link.
  - If Verify: we copy the URL to clipboard and call the backend.
    - Safe/Legitimate: bar turns green; auto-open after 1s.
    - Suspicious or confidence < 0.7: bar turns yellow; open `.../verify?url=...` in background and navigate to `.../warning?url=...`.
    - Phishing/Malicious: bar turns red; we go to packaged `warning.html`.
- Caching: results saved in `chrome.storage.local` for 5 minutes per URL.
- Middle-click / Ctrl+click: after verification, we respect opening in a new tab.

## Change endpoints
- Edit constants at the top of `content.js`.
