@echo off
chcp 65001 >nul
title 壁越えトンネル

where python >nul 2>nul
if errorlevel 1 (
    echo Python が見つかりません。https://www.python.org/ から Python 3.9 以降をインストールしてください。
    pause
    exit /b 1
)

python -c "import paramiko, websockets" >nul 2>nul
if errorlevel 1 (
    echo 初回実行のためパッケージをインストール中...
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
)

python app.py
pause
