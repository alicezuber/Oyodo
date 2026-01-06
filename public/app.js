const subscribeBtn = document.getElementById('subscribeBtn');
const statusIndicator = document.getElementById('statusIndicator');
const statusText = document.getElementById('statusText');
const detailSection = document.getElementById('detailSection');
const detailTitle = document.getElementById('detailTitle');
const detailBody = document.getElementById('detailBody');
const detailContent = document.getElementById('detailContent');
const detailTime = document.getElementById('detailTime');
const closeDetailBtn = document.getElementById('closeDetailBtn');
const notificationList = document.getElementById('notificationList');

let swRegistration = null;
let isSubscribed = false;

async function init() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        updateStatus('unsupported', '瀏覽器不支援 Web Push');
        return;
    }

    try {
        swRegistration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered');

        const subscription = await swRegistration.pushManager.getSubscription();
        isSubscribed = subscription !== null;
        updateUI();

        checkUrlForNotification();
        loadNotificationHistory();
    } catch (err) {
        console.error('Init failed:', err);
        updateStatus('unsupported', '初始化失敗');
    }
}

function updateStatus(state, text) {
    statusIndicator.className = 'status-indicator ' + state;
    statusText.textContent = text;
}

function updateUI() {
    if (isSubscribed) {
        updateStatus('subscribed', '已訂閱通知');
        subscribeBtn.textContent = '取消訂閱';
    } else {
        updateStatus('unsubscribed', '未訂閱');
        subscribeBtn.textContent = '訂閱通知';
    }
    subscribeBtn.disabled = false;
}

async function subscribe() {
    try {
        const response = await fetch('/api/vapid-public-key');
        const { publicKey } = await response.json();

        const subscription = await swRegistration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey)
        });

        await fetch('/api/subscribe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(subscription)
        });

        isSubscribed = true;
        updateUI();
    } catch (err) {
        console.error('Subscribe failed:', err);
        alert('訂閱失敗: ' + err.message);
    }
}

async function unsubscribe() {
    try {
        const subscription = await swRegistration.pushManager.getSubscription();
        if (subscription) {
            await subscription.unsubscribe();
            await fetch('/api/subscribe', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: subscription.endpoint })
            });
        }
        isSubscribed = false;
        updateUI();
    } catch (err) {
        console.error('Unsubscribe failed:', err);
        alert('取消訂閱失敗: ' + err.message);
    }
}

subscribeBtn.addEventListener('click', () => {
    if (isSubscribed) {
        unsubscribe();
    } else {
        subscribe();
    }
});

closeDetailBtn.addEventListener('click', () => {
    detailSection.style.display = 'none';
    history.replaceState(null, '', '/');
});

function checkUrlForNotification() {
    const params = new URLSearchParams(window.location.search);
    const notificationId = params.get('notification');
    if (notificationId) {
        showNotificationDetail(notificationId);
    }
}

async function showNotificationDetail(id) {
    try {
        const response = await fetch(`/api/notification/${id}`);
        if (!response.ok) {
            throw new Error('Notification not found');
        }
        const data = await response.json();

        detailTitle.textContent = data.title;
        detailBody.textContent = data.body;
        detailContent.textContent = data.detail || '無詳細內容';
        detailTime.textContent = new Date(data.createdAt).toLocaleString('zh-TW');

        detailSection.style.display = 'block';
        detailSection.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        console.error('Load detail failed:', err);
    }
}

async function loadNotificationHistory() {
    try {
        const response = await fetch('/api/notifications');
        const notifications = await response.json();

        if (notifications.length === 0) {
            notificationList.innerHTML = '<p class="empty-state">尚無通知記錄</p>';
            return;
        }

        notificationList.innerHTML = notifications.map(n => `
            <div class="notification-item" data-id="${n.id}">
                <h4>${escapeHtml(n.title)}${n.detail ? '<span class="has-detail">有詳情</span>' : ''}</h4>
                <p>${escapeHtml(n.body)}</p>
                <time>${new Date(n.createdAt).toLocaleString('zh-TW')}</time>
            </div>
        `).join('');

        notificationList.querySelectorAll('.notification-item').forEach(item => {
            item.addEventListener('click', () => {
                const id = item.dataset.id;
                history.pushState(null, '', `?notification=${id}`);
                showNotificationDetail(id);
            });
        });
    } catch (err) {
        console.error('Load history failed:', err);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

navigator.serviceWorker.addEventListener('message', (event) => {
    if (event.data.type === 'NOTIFICATION_CLICK') {
        showNotificationDetail(event.data.notificationId);
        loadNotificationHistory();
    }
});

init();
