require('dotenv').config();
const express = require('express');
const webpush = require('web-push');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

const poolOyodo = mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME_OYODO,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

webpush.setVapidDetails(
    process.env.VAPID_EMAIL || 'mailto:admin@example.com',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
);

app.use(express.json());
app.use(express.static('public'));

async function getSubscriptions() {
    const [rows] = await poolOyodo.query('SELECT * FROM subscriptions');
    return rows.map(row => ({
        endpoint: row.endpoint,
        keys: {
            p256dh: row.p256dh,
            auth: row.auth
        }
    }));
}

async function addSubscription(subscription) {
    await poolOyodo.query(
        'INSERT IGNORE INTO subscriptions (endpoint, p256dh, auth) VALUES (?, ?, ?)',
        [subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth]
    );
}

async function removeSubscription(endpoint) {
    await poolOyodo.query('DELETE FROM subscriptions WHERE endpoint = ?', [endpoint]);
}

async function saveNotification(id, title, body, detail) {
    await poolOyodo.query(
        'INSERT INTO notifications (id, title, body, detail, created_at) VALUES (?, ?, ?, ?, NOW())',
        [id, title, body, detail]
    );
}

async function getNotification(id) {
    const [rows] = await poolOyodo.query('SELECT * FROM notifications WHERE id = ?', [id]);
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
        title: row.title,
        body: row.body,
        detail: row.detail,
        createdAt: row.created_at
    };
}

async function getAllNotifications() {
    const [rows] = await poolOyodo.query('SELECT * FROM notifications ORDER BY created_at DESC');
    return rows.map(row => ({
        id: row.id,
        title: row.title,
        body: row.body,
        detail: row.detail,
        createdAt: row.created_at
    }));
}

function apiKeyAuth(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ error: 'Invalid or missing API key' });
    }
    next();
}

app.get('/api/vapid-public-key', (req, res) => {
    res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

app.post('/api/subscribe', async (req, res) => {
    const subscription = req.body;
    
    if (!subscription || !subscription.endpoint) {
        return res.status(400).json({ error: 'Invalid subscription' });
    }
    
    try {
        await addSubscription(subscription);
        console.log('New subscription added');
        res.json({ success: true });
    } catch (err) {
        console.error('Subscribe error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/subscribe', async (req, res) => {
    const { endpoint } = req.body;
    
    if (!endpoint) {
        return res.status(400).json({ error: 'Endpoint required' });
    }
    
    try {
        await removeSubscription(endpoint);
        res.json({ success: true });
    } catch (err) {
        console.error('Unsubscribe error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/notify', apiKeyAuth, async (req, res) => {
    const { title, body, detail } = req.body;
    
    if (!title || !body) {
        return res.status(400).json({ error: 'Title and body are required' });
    }
    
    const notificationId = uuidv4();
    
    try {
        await saveNotification(notificationId, title, body, detail || null);
        
        const payload = JSON.stringify({
            title,
            body,
            notificationId
        });
        
        const subscriptions = await getSubscriptions();
        const results = { success: 0, failed: 0 };
        const expiredEndpoints = [];
        
        for (const subscription of subscriptions) {
            try {
                await webpush.sendNotification(subscription, payload);
                results.success++;
            } catch (err) {
                console.error('Push failed:', err.message);
                results.failed++;
                if (err.statusCode === 410 || err.statusCode === 404) {
                    expiredEndpoints.push(subscription.endpoint);
                }
            }
        }
        
        for (const endpoint of expiredEndpoints) {
            await removeSubscription(endpoint);
        }
        
        res.json({
            success: true,
            notificationId,
            delivered: results.success,
            failed: results.failed
        });
    } catch (err) {
        console.error('Notify error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/notification/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const notification = await getNotification(id);
        if (!notification) {
            return res.status(404).json({ error: 'Notification not found' });
        }
        res.json(notification);
    } catch (err) {
        console.error('Get notification error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/notifications', async (req, res) => {
    try {
        const notifications = await getAllNotifications();
        res.json(notifications);
    } catch (err) {
        console.error('Get notifications error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Oyodo Push Service running on 0.0.0.0:${PORT}`);
    
    if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
        console.warn('\n⚠️  VAPID keys not configured!');
        console.warn('Run: npm run generate-vapid');
        console.warn('Then add the keys to your .env file\n');
    }
    
    if (!process.env.API_KEY) {
        console.warn('⚠️  API_KEY not configured! External notifications will fail.\n');
    }
});
