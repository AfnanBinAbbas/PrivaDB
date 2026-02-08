# Data Whisperer Backend Setup

This document explains how to set up and run the Python backend for Data Whisperer.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Install Playwright browsers:
```bash
playwright install chromium
```

If Playwright installation fails, you can also run:
```bash
python -m playwright install chromium
```

## Running the Backend

1. Start the FastAPI server:
```bash
python backend.py
```

Or using uvicorn directly:
```bash
uvicorn backend:app --reload --host 0.0.0.0 --port 8000
```

The backend will be available at `http://localhost:8000`

2. The API documentation will be available at:
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### `/api/scan` (POST)
Scan a domain and extract IndexedDB data and network requests.

**Request Body:**
```json
{
  "domain": "example.com",
  "scenario": "fresh_browser",
  "use_incognito": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "timestamp": "...",
    "databases": [...],
    "endpoints": [...]
  }
}
```

### `/api/analyze` (POST)
Analyze extracted data from multiple scenarios.

**Request Body:**
```json
{
  "scenario1_file": "data/fresh_browser.json",
  "scenario2_file": "data/return_visit.json",
  "scenario3_file": "data/cleared_browser.json"
}
```

### `/api/scan-and-analyze` (POST)
Complete workflow: Scan domain in 3 scenarios and analyze results.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

## Frontend Configuration

1. Make sure your frontend can reach the backend. By default, the frontend expects the backend at `http://localhost:8000`.

2. To change the backend URL, create a `.env` file in the frontend directory:
```
VITE_BACKEND_API_URL=http://localhost:8000
```

3. The frontend will automatically use the Python backend when calling `scannerApi.scanDomain()`. If the backend is unavailable, it will fall back to the Supabase function.

## Troubleshooting

- **CORS errors**: Make sure the backend CORS middleware is configured with the correct frontend URL (default: `http://localhost:5173`)
- **Playwright not found**: Run `playwright install chromium` or `python -m playwright install chromium`
- **Port already in use**: Change the port in `backend.py` or use `--port` with uvicorn
