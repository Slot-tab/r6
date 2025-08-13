@echo off
REM ==============================
REM GitHub Auto Push Script
REM ==============================

REM Change directory to your local GitHub repository
cd /d "C:\Users\Cristian\Desktop\~"

REM Make sure we are in a git repo
if not exist .git (
    echo This folder is not a Git repository.
    pause
    exit /b
)

REM Stage all changes
git add .

REM Commit with timestamp from %date% and %time%
set commitmsg=Auto commit on %date% %time%
git commit -m "%commitmsg%"

REM Push to GitHub
git push origin main

pause
