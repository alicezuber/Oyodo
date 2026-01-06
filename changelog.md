# Changelog

## [0.2.0] - 2026-01-07

### Changed
- 資料儲存從 JSON 檔案遷移至 MySQL 資料庫
- 使用 mysql2 連接池管理資料庫連線

### Added
- `schema.sql` 資料庫結構定義
- `setting.bat` 一鍵初始化腳本（生成 VAPID、API Key、建立 .env）
- MySQL 連線設定（DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME_OYODO）

## [0.1.0] - 2026-01-07

### Added
- 初始版本
- Web Push 訂閱/取消訂閱功能
- `/api/notify` 接收外部通知請求（需 API Key 認證）
- 通知詳情機制：API 可傳入 `detail` 欄位，點擊通知後在網頁顯示
- 通知歷史列表
- VAPID 金鑰生成腳本
- 響應式前端 UI
