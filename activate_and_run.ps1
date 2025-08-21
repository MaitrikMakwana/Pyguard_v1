# PyGuard Virtual Environment Launcher
Write-Host "PyGuard Virtual Environment Launcher" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Run the launcher
Write-Host "Starting PyGuard..." -ForegroundColor Yellow
python run_in_venv.py

# Keep console open
Write-Host "Press any key to continue..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
