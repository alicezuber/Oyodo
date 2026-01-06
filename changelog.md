# Changelog

## [0.3.0] - 2026-01-07

### Changed
- 全新 UI 設計，針對 iPhone 優化
- 底部 Tab 導航（首頁、通知、發送）
- 所有通知都儲存到資料庫（不只有帶 detail 的）
- 詳情頁面改為全螢幕 Modal 滑入效果

### Added
- 發送通知 GUI 頁面（無需使用 API 工具）
- 首頁統計卡片（總通知數、今日通知）
- 最近通知快速預覽
- PWA manifest.json 支援
- 相對時間顯示（剛剛、X 分鐘前）
- API Key 本地儲存功能

## [0.2.1] - 2026-01-07

### Changed
- 伺服器監聽位址改為 `0.0.0.0`，可供外部裝置存取

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
