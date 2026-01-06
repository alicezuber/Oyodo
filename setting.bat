@echo off
chcp 65001 >nul
echo ========================================
echo   Oyodo Push Service - 初始化設定
echo ========================================
echo.

:: 檢查 Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [錯誤] 未找到 Node.js，請先安裝 Node.js
    pause
    exit /b 1
)

echo [1/4] 安裝 npm 依賴...
call npm install
if %errorlevel% neq 0 (
    echo [錯誤] npm install 失敗
    pause
    exit /b 1
)
echo.

echo [2/4] 生成 VAPID 金鑰...
echo.
for /f "tokens=*" %%i in ('node -e "const wp = require('web-push'); const keys = wp.generateVAPIDKeys(); console.log(keys.publicKey + '|' + keys.privateKey);"') do set VAPID_KEYS=%%i
for /f "tokens=1,2 delims=|" %%a in ("%VAPID_KEYS%") do (
    set VAPID_PUBLIC=%%a
    set VAPID_PRIVATE=%%b
)

echo VAPID_PUBLIC_KEY=%VAPID_PUBLIC%
echo VAPID_PRIVATE_KEY=%VAPID_PRIVATE%
echo.

echo [3/4] 生成 API 金鑰...
for /f "tokens=*" %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'));"') do set API_KEY=%%i
echo API_KEY=%API_KEY%
echo.

echo [4/4] 建立 .env 檔案...
if exist .env (
    echo [警告] .env 已存在，備份為 .env.backup
    copy .env .env.backup >nul
)

(
echo # VAPID Keys
echo VAPID_PUBLIC_KEY=%VAPID_PUBLIC%
echo VAPID_PRIVATE_KEY=%VAPID_PRIVATE%
echo VAPID_EMAIL=mailto:admin@example.com
echo.
echo # API Authentication
echo API_KEY=%API_KEY%
echo.
echo # Server
echo PORT=3000
echo.
echo # MySQL Database
echo DB_HOST=43.167.240.118
echo DB_PORT=32405
echo DB_USER=root
echo DB_PASSWORD=5wYpcmgxk8Ro3TvG6ysW1hE0Sd924Ci7
echo DB_NAME_CORE=sasebo_core
echo DB_NAME_OYODO=sasebo_oyodo
) > .env

echo.
echo ========================================
echo   設定完成！
echo ========================================
echo.
echo 請記住你的 API 金鑰：
echo   %API_KEY%
echo.
echo 啟動服務：npm start
echo 開發模式：npm run dev
echo.
echo ----------------------------------------
echo 請在 MySQL 中執行 schema.sql 建立資料表：
echo   sasebo_oyodo 資料庫
echo ----------------------------------------
echo.
pause
