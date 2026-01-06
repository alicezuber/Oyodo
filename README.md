# Oyodo Push Service

Web Push 通知代理服務 - 接收外部 API 請求並廣播 Web Push 通知給所有訂閱用戶。

## 功能

- **訂閱管理** - 用戶可在網頁上訂閱/取消訂閱通知
- **API 接收** - 接收外部服務的 POST 請求發送通知
- **詳情機制** - 通知可附帶詳情，點擊通知後在網頁顯示
- **歷史記錄** - 查看所有通知歷史

## 快速開始

### 1. 安裝依賴

```bash
npm install
```

### 2. 生成 VAPID 金鑰

```bash
npm run generate-vapid
```

### 3. 設定環境變數

複製 `.env.example` 為 `.env`，填入：

```env
VAPID_PUBLIC_KEY=<生成的公鑰>
VAPID_PRIVATE_KEY=<生成的私鑰>
VAPID_EMAIL=mailto:your-email@example.com
API_KEY=<你的 API 金鑰>
PORT=3000
```

### 4. 啟動服務

```bash
npm start
# 或開發模式
npm run dev
```

### 5. 訪問網頁

打開 `http://localhost:3000` 訂閱通知

## API 文檔

### 發送通知

```http
POST /api/notify
X-API-Key: <your-api-key>
Content-Type: application/json

{
    "title": "通知標題",
    "body": "通知內文",
    "detail": "點擊後顯示的詳細內容（可選）"
}
```

**回應：**

```json
{
    "success": true,
    "notificationId": "uuid",
    "delivered": 5,
    "failed": 0
}
```

### 取得通知詳情

```http
GET /api/notification/:id
```

### 取得通知歷史

```http
GET /api/notifications
```

### 取得 VAPID 公鑰

```http
GET /api/vapid-public-key
```

### 訂閱推播

```http
POST /api/subscribe
Content-Type: application/json

{
    "endpoint": "...",
    "keys": { "p256dh": "...", "auth": "..." }
}
```

### 取消訂閱

```http
DELETE /api/subscribe
Content-Type: application/json

{
    "endpoint": "..."
}
```

## 外部服務整合範例

### cURL

```bash
curl -X POST http://localhost:3000/api/notify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"title":"系統通知","body":"有新訊息","detail":"這是詳細內容..."}'
```

### Python

```python
import requests

response = requests.post(
    'http://localhost:3000/api/notify',
    headers={'X-API-Key': 'your-api-key'},
    json={
        'title': '系統通知',
        'body': '有新訊息',
        'detail': '這是詳細內容...'
    }
)
print(response.json())
```

### Node.js

```javascript
fetch('http://localhost:3000/api/notify', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'your-api-key'
    },
    body: JSON.stringify({
        title: '系統通知',
        body: '有新訊息',
        detail: '這是詳細內容...'
    })
});
```

## 資料儲存

目前使用 JSON 檔案儲存：

- `data/subscriptions.json` - 訂閱資料
- `data/notifications.json` - 通知詳情

未來將遷移至 SQL 資料庫。

## 注意事項

- Web Push 需要 HTTPS 環境（localhost 除外）
- 生產環境請使用強隨機 API_KEY
- VAPID 金鑰請妥善保管，不要外洩
