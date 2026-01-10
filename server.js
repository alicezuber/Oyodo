require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const webpush = require('web-push');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const app = express();
const PORT = process.env.PORT || 3000;
const ZITADEL_ISSUER = (process.env.ZITADEL_ISSUER || 'https://auth.baiyun.cv').replace(/\/$/, '');
const ZITADEL_CLIENT_ID = process.env.ZITADEL_CLIENT_ID || '354957630411702491';
const jwksUri = new URL('/oauth/v2/keys', ZITADEL_ISSUER);
const remoteJwks = createRemoteJWKSet(jwksUri);

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
app.get(['/auth/callback'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const DEFAULT_CHANNEL = 'global';
const ROLE_PRIORITY = ['admin', 'moderator', 'subscriber'];
const SEND_ALLOWED_ROLES = ['admin', 'moderator'];
const PASSCODE_LENGTH = 6;

function normalizeChannel(value, fallback = DEFAULT_CHANNEL) {
    const normalized = (value ?? '').trim();
    if (!normalized) return fallback;
    return normalized.toLowerCase();
}

function normalizeRecipient(value) {
    const normalized = (value ?? '').trim();
    return normalized || null;
}

function hashPasscode(passcode) {
    return crypto.createHash('sha256').update(String(passcode)).digest('hex');
}

function extractRoles(payload) {
    if (!payload) return [];
    const raw = payload['urn:zitadel:iam:org:project:roles'];
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') return [raw];
    if (typeof raw === 'object') {
        return Object.entries(raw)
            .filter(([, value]) => value === true || value === 1 || value === 'true')
            .map(([key]) => key);
    }
    return [];
}

function getPrimaryRole(roles = []) {
    for (const role of ROLE_PRIORITY) {
        if (roles.includes(role)) return role;
    }
    return roles[0] || null;
}

async function verifyBearerToken(authHeader) {
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
        const err = new Error('Missing bearer token');
        err.statusCode = 401;
        throw err;
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
        const err = new Error('Invalid bearer token');
        err.statusCode = 401;
        throw err;
    }

    try {
        const { payload } = await jwtVerify(token, remoteJwks, {
            issuer: ZITADEL_ISSUER,
            audience: ZITADEL_CLIENT_ID
        });
        return payload;
    } catch (error) {
        const err = new Error('Token verification failed');
        err.statusCode = 401;
        throw err;
    }
}

function buildUserProfile(payload) {
    if (!payload) return null;
    const roles = extractRoles(payload);
    return {
        id: payload.sub || null,
        email: payload.email || null,
        name: payload.name || payload.preferred_username || null,
        roles,
        primaryRole: getPrimaryRole(roles)
    };
}

async function oidcAuth(req, res, next) {
    try {
        const payload = await verifyBearerToken(req.headers.authorization);
        const user = buildUserProfile(payload);
        if (!user) {
            return res.status(401).json({ error: 'Failed to build user profile' });
        }
        req.oidcUser = user;
        next();
    } catch (err) {
        const status = err.statusCode || 401;
        res.status(status).json({ error: err.message || 'Authorization failed' });
    }
}

function requireRoles(allowedRoles = []) {
    const normalized = Array.isArray(allowedRoles) ? allowedRoles.filter(Boolean) : [allowedRoles].filter(Boolean);
    const allowedSet = new Set(normalized);
    return (req, res, next) => {
        const user = req.oidcUser;
        if (!user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        if (allowedSet.size === 0) {
            return next();
        }
        const hasAllowedRole = (user.roles || []).some(role => allowedSet.has(role));
        if (!hasAllowedRole) {
            return res.status(403).json({ error: 'Insufficient role' });
        }
        next();
    };
}

async function getSubscriptions(filters = {}) {
    const { channel, recipientId } = filters;
    const conditions = [];
    const params = [];
    let query = `
        SELECT endpoint, p256dh, auth, channel, recipient_id
        FROM subscriptions
    `;

    if (recipientId) {
        conditions.push('LOWER(recipient_id) = LOWER(?)');
        params.push(recipientId.trim());
    }

    if (channel) {
        conditions.push('channel = ?');
        params.push(normalizeChannel(channel, null));
    }

    if (conditions.length > 0) {
        query += ' WHERE ' + conditions.join(' AND ');
    }

    const [rows] = await poolOyodo.query(query, params);
    return rows.map(row => ({
        endpoint: row.endpoint,
        keys: {
            p256dh: row.p256dh,
            auth: row.auth
        },
        channel: row.channel || DEFAULT_CHANNEL,
        recipientId: row.recipient_id || null
    }));
}

async function addSubscription(subscription, channel, recipientId) {
    const resolvedChannel = normalizeChannel(channel);
    const resolvedRecipient = normalizeRecipient(recipientId);
    await poolOyodo.query(
        `INSERT INTO subscriptions (endpoint, p256dh, auth, channel, recipient_id)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            p256dh = VALUES(p256dh),
            auth = VALUES(auth),
            channel = VALUES(channel),
            recipient_id = VALUES(recipient_id)`,
        [subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth, resolvedChannel, resolvedRecipient]
    );
}

async function removeSubscription(endpoint) {
    await poolOyodo.query('DELETE FROM subscriptions WHERE endpoint = ?', [endpoint]);
}

async function saveNotification(id, title, body, detail, channel, recipientId) {
    await poolOyodo.query(
        'INSERT INTO notifications (id, title, body, detail, channel, recipient_id, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
        [id, title, body, detail, channel || null, recipientId || null]
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
        channel: row.channel,
        recipientId: row.recipient_id,
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
        channel: row.channel,
        recipientId: row.recipient_id,
        createdAt: row.created_at
    }));
}

async function broadcastNotification({ title, body, detail, channel, recipientId }) {
    if (!title || !body) {
        const error = new Error('Title and body are required');
        error.statusCode = 400;
        throw error;
    }

    const notificationId = uuidv4();
    const targetChannel = normalizeChannel(channel, null);
    const targetRecipient = normalizeRecipient(recipientId);

    await saveNotification(notificationId, title, body, detail || null, targetChannel, targetRecipient);

    const payload = JSON.stringify({
        title,
        body,
        notificationId,
        channel: targetChannel,
        recipientId: targetRecipient
    });

    const recipients = await getSubscriptions({
        channel: targetChannel || undefined,
        recipientId: targetRecipient || undefined
    });

    const results = { success: 0, failed: 0 };
    const expiredEndpoints = [];

    for (const subscription of recipients) {
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

    return {
        notificationId,
        delivered: results.success,
        failed: results.failed
    };
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

app.get('/api/channels/mine', oidcAuth, async (req, res) => {
    try {
        const channels = await getUserChannels(req.oidcUser.id);
        res.json({ channels });
    } catch (err) {
        console.error('Channels mine error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/channels/join', oidcAuth, async (req, res) => {
    const { channel, passcode } = req.body || {};
    const normalizedChannel = normalizeChannel(channel, null);

    if (!normalizedChannel || normalizedChannel === DEFAULT_CHANNEL) {
        return res.status(400).json({ error: 'Invalid channel' });
    }
    if (!passcode || !/^\d+$/.test(String(passcode)) || String(passcode).length !== PASSCODE_LENGTH) {
        return res.status(400).json({ error: `Passcode must be ${PASSCODE_LENGTH} digits` });
    }

    try {
        const key = await getChannelKey(normalizedChannel);
        if (!key) {
            return res.status(404).json({ error: 'Channel not found' });
        }
        const hashed = hashPasscode(passcode);
        if (hashed !== key.passcode_hash) {
            return res.status(403).json({ error: 'Invalid passcode' });
        }

        await addChannelMembership(req.oidcUser.id, normalizedChannel);
        const channels = await getUserChannels(req.oidcUser.id);
        res.json({ success: true, channels });
    } catch (err) {
        console.error('Join channel error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/auth/profile', oidcAuth, (req, res) => {
    res.json({ user: req.oidcUser });
});

app.post('/api/subscribe', async (req, res) => {
    const payload = req.body || {};
    const subscription = payload.subscription || payload;
    const requestedChannel = normalizeChannel(payload.channel, DEFAULT_CHANNEL);

    if (!subscription || !subscription.endpoint) {
        return res.status(400).json({ error: 'Invalid subscription' });
    }

    try {
        const user = await authenticateRequest(req, { optional: true });
        let resolvedChannel = DEFAULT_CHANNEL;
        let resolvedRecipient = null;

        if (user) {
            resolvedChannel = requestedChannel;
            if (resolvedChannel !== DEFAULT_CHANNEL) {
                const allowed = await userHasChannel(user.id, resolvedChannel);
                if (!allowed) {
                    return res.status(403).json({ error: 'Channel membership required' });
                }
            }
            resolvedRecipient = user.id;
        }

        await addSubscription(subscription, resolvedChannel, resolvedRecipient);
        console.log('New subscription added');
        res.json({ success: true, channel: resolvedChannel });
    } catch (err) {
        console.error('Subscribe error:', err.message);
        const status = err.statusCode || 500;
        res.status(status).json({ error: status === 400 ? err.message : 'Database error' });
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
    try {
        const result = await broadcastNotification(req.body || {});
        res.json({
            success: true,
            ...result
        });
    } catch (err) {
        console.error('Notify error:', err.message);
        const status = err.statusCode || 500;
        res.status(status).json({ error: status === 400 ? err.message : 'Server error' });
    }
});

app.post('/api/webhook', apiKeyAuth, async (req, res) => {
    try {
        await broadcastNotification(req.body || {});
        res.status(202).end();
    } catch (err) {
        console.error('Webhook error:', err.message);
        const status = err.statusCode || 500;
        res.status(status).json({ error: status === 400 ? err.message : 'Server error' });
    }
});

app.post('/api/send', oidcAuth, requireRoles(SEND_ALLOWED_ROLES), async (req, res) => {
    try {
        const result = await broadcastNotification(req.body || {});
        res.json({
            success: true,
            ...result
        });
    } catch (err) {
        console.error('Send error:', err.message);
        const status = err.statusCode || 500;
        res.status(status).json({ error: status === 400 ? err.message : 'Server error' });
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
