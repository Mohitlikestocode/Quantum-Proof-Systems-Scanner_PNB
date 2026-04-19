# Quantum Shield PNB

Primary project documentation is in [Documentation/README.md](Documentation/README.md).

## Run Locally

The app uses a Vite frontend and a FastAPI backend.

```bash
npm install
npm run dev
```

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```