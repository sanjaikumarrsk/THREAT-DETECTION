# Cyber Threat Defense System - PowerShell Startup Script
# This script starts both backend and frontend with a single command

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cyber Threat Defense System - Starting" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "src\main.py")) {
    Write-Host "ERROR: src\main.py not found. Please run this script from the CyberThreatDefense directory." -ForegroundColor Red
    exit 1
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "[SETUP] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
Write-Host "[SETUP] Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Install backend dependencies
Write-Host "[SETUP] Installing backend dependencies..." -ForegroundColor Yellow
pip install -q -r requirements.txt

# Start backend in a new PowerShell window
Write-Host ""
Write-Host "[1/3] Starting Backend (Flask API on port 5000)..." -ForegroundColor Green
Write-Host ""

$backendScript = @"
# Activate virtual environment
& ".\venv\Scripts\Activate.ps1"

# Start Flask
Write-Host "[BACKEND] Flask API Server Starting..." -ForegroundColor Green
Write-Host "Backend URL: http://localhost:5000" -ForegroundColor Cyan
Write-Host ""
python -m flask run --host=0.0.0.0 --port=5000

Write-Host ""
Write-Host "Backend stopped. Press any key to close this window..." -ForegroundColor Yellow
Read-Host
"@

$backendPath = Join-Path $PSScriptRoot "venv\Scripts\Activate.ps1"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendScript

# Wait for backend to start
Start-Sleep -Seconds 3

# Start frontend
Write-Host "[2/3] Starting IBM Frontend (Vite on port 3000)..." -ForegroundColor Green
Write-Host ""

$frontendScript = @"
cd "$PSScriptRoot\ibm frontend"

if (-not (Test-Path "node_modules")) {
    Write-Host "[FRONTEND] Installing npm dependencies (this may take a minute)..." -ForegroundColor Yellow
    npm install --silent
}

Write-Host "[FRONTEND] IBM Vite Dev Server Starting..." -ForegroundColor Green
Write-Host "Frontend URL: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
npm run dev -- --host 0.0.0.0 --port 3000

Write-Host ""
Write-Host "Frontend stopped. Press any key to close this window..." -ForegroundColor Yellow
Read-Host
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendScript

# Wait for frontend to start
Start-Sleep -Seconds 5

# Open browser
Write-Host "[3/3] Opening application in browser..." -ForegroundColor Green
Write-Host ""

Start-Sleep -Seconds 1
Start-Process "http://localhost:3000"

# Display summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Application Starting!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Frontend:  " -ForegroundColor White -NoNewline
Write-Host "http://localhost:3000" -ForegroundColor Green
Write-Host "Backend:   " -ForegroundColor White -NoNewline
Write-Host "http://localhost:5000" -ForegroundColor Green
Write-Host ""
Write-Host "Two PowerShell windows have been opened:" -ForegroundColor White
Write-Host "  1. Backend Server (Flask API)" -ForegroundColor Yellow
Write-Host "  2. Frontend Server (React Dev Server)" -ForegroundColor Yellow
Write-Host ""
Write-Host "To stop the application:" -ForegroundColor White
Write-Host "  1. In backend window: Press Ctrl+C" -ForegroundColor Yellow
Write-Host "  2. In frontend window: Press Ctrl+C" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to close this window..." -ForegroundColor Cyan
Write-Host ""
Read-Host
