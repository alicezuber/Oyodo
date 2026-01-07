const subscribeBtn = document.getElementById('subscribeBtn');
const statusBadge = document.getElementById('statusBadge');
const statusText = document.getElementById('statusText');
const detailModal = document.getElementById('detailModal');
const detailTitle = document.getElementById('detailTitle');
const detailBody = document.getElementById('detailBody');
const detailContent = document.getElementById('detailContent');
const detailTime = document.getElementById('detailTime');
const closeDetailBtn = document.getElementById('closeDetailBtn');
const notificationList = document.getElementById('notificationList');
const recentList = document.getElementById('recentList');
const statTotal = document.getElementById('statTotal');
const statToday = document.getElementById('statToday');

const sendForm = document.getElementById('sendForm');
const apiKeyInput = document.getElementById('apiKeyInput');
const titleInput = document.getElementById('titleInput');
const bodyInput = document.getElementById('bodyInput');
const detailInput = document.getElementById('detailInput');
const titleCount = document.getElementById('titleCount');
const bodyCount = document.getElementById('bodyCount');
const detailCount = document.getElementById('detailCount');
const toggleApiKey = document.getElementById('toggleApiKey');
const sendResult = document.getElementById('sendResult');
const sendBtn = document.getElementById('sendBtn');
const tabItems = Array.from(document.querySelectorAll('.tab-item'));
const tabPanes = {
    home: document.getElementById('homePane'),
    history: document.getElementById('historyPane'),
    send: document.getElementById('sendPane')
};
const sendTabItem = tabItems.find(item => item.dataset.tab === 'send');

let swRegistration = null;
let isSubscribed = false;
let allNotifications = [];
let activeTab = 'home';
let currentMode = null;
let resizeDebounce = null;

const MODE_BREAKPOINT = 900;

async function init() {
    initTabs();
    initSendForm();
    setupModeDetection();
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        updateStatus('unsupported', '不支援推播');
        return;
    }

    try {
        swRegistration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered');

        const subscription = await swRegistration.pushManager.getSubscription();
        isSubscribed = subscription !== null;
        updateUI();

        await loadNotificationHistory();
        checkUrlForNotification();
    } catch (err) {
        console.error('Init failed:', err);
        updateStatus('unsupported', '初始化失敗');
    }
}

function initTabs() {
    tabItems.forEach(item => {
        item.addEventListener('click', () => {
            if (item.classList.contains('tab-item--hidden')) return;
            const tabId = item.dataset.tab;
            activateTab(tabId);
        });
    });
    activateTab('home');
}

function initSendForm() {
    const savedApiKey = localStorage.getItem('oyodo_api_key');
    if (savedApiKey) {
        apiKeyInput.value = savedApiKey;
    }
    
    titleInput.addEventListener('input', () => {
        titleCount.textContent = titleInput.value.length;
    });
    
    bodyInput.addEventListener('input', () => {
        bodyCount.textContent = bodyInput.value.length;
    });
    
    detailInput.addEventListener('input', () => {
        detailCount.textContent = detailInput.value.length;
    });
    
    toggleApiKey.addEventListener('click', () => {
        apiKeyInput.type = apiKeyInput.type === 'password' ? 'text' : 'password';
    });
    
    sendForm.addEventListener('submit', handleSendNotification);
}

async function handleSendNotification(e) {
    e.preventDefault();
    
    const apiKey = apiKeyInput.value.trim();
    const title = titleInput.value.trim();
    const body = bodyInput.value.trim();
    const detail = detailInput.value.trim();
    
    if (!apiKey) {
        showSendResult('error', '請輸入 API 金鑰');
        return;
    }
    
    if (!title || !body) {
        showSendResult('error', '標題和內文為必填');
        return;
    }
    
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span>發送中...</span>';
    
    try {
        localStorage.setItem('oyodo_api_key', apiKey);
        
        const response = await fetch('/api/notify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': apiKey
            },
            body: JSON.stringify({ title, body, detail: detail || undefined })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || '發送失敗');
        }
        
        showSendResult('success', `發送成功！已送達 ${data.delivered} 位訂閱者`);
        titleInput.value = '';
        bodyInput.value = '';
        detailInput.value = '';
        titleCount.textContent = '0';
        bodyCount.textContent = '0';
        detailCount.textContent = '0';
        
        await loadNotificationHistory();
    } catch (err) {
        console.error('Send failed:', err);
        showSendResult('error', err.message);
    } finally {
        sendBtn.disabled = false;
        sendBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
            發送通知
        `;
    }
}

function showSendResult(type, message) {
    sendResult.className = 'send-result ' + type;
    sendResult.textContent = message;
    sendResult.style.display = 'block';
    
    setTimeout(() => {
        sendResult.style.display = 'none';
    }, 5000);
}

function updateStatus(state, text) {
    statusBadge.className = 'status-badge ' + state;
    statusText.textContent = text;
}

function setupModeDetection() {
    determineMode();
    window.addEventListener('resize', () => {
        clearTimeout(resizeDebounce);
        resizeDebounce = setTimeout(determineMode, 150);
    });
}

function determineMode() {
    const width = window.innerWidth;
    const newMode = width >= MODE_BREAKPOINT ? 'desktop' : 'mobile';
    if (newMode !== currentMode) {
        applyMode(newMode);
    }
}

function applyMode(mode) {
    currentMode = mode;
    document.body.dataset.mode = mode;
    
    if (mode === 'desktop') {
        sendTabItem?.classList.remove('tab-item--hidden');
        tabPanes.send?.classList.remove('tab-pane--hidden');
        activateTab('home');
    } else {
        sendTabItem?.classList.add('tab-item--hidden');
        tabPanes.send?.classList.add('tab-pane--hidden');
        if (activeTab === 'send') {
            activateTab('home');
        } else {
            ensureActiveTab();
        }
    }
    ensureActiveTab();
}

function activateTab(tabId) {
    const targetItem = tabItems.find(item => item.dataset.tab === tabId);
    const targetPane = tabPanes[tabId];
    
    if (!targetItem || !targetPane) return;
    if (targetItem.classList.contains('tab-item--hidden')) return;
    if (targetPane.classList.contains('tab-pane--hidden')) return;
    
    tabItems.forEach(item => item.classList.remove('active'));
    Object.values(tabPanes).forEach(pane => pane.classList.remove('active'));
    
    targetItem.classList.add('active');
    targetPane.classList.add('active');
    activeTab = tabId;
}

function ensureActiveTab() {
    const visibleTabs = tabItems.filter(item => !item.classList.contains('tab-item--hidden'));
    if (visibleTabs.length === 0) return;
    
    const hasActive = visibleTabs.some(item => item.dataset.tab === activeTab);
    if (!hasActive) {
        activateTab(visibleTabs[0].dataset.tab);
    }
}

function updateUI() {
    if (isSubscribed) {
        updateStatus('subscribed', '已訂閱');
        subscribeBtn.textContent = '取消訂閱';
    } else {
        updateStatus('unsubscribed', '未訂閱');
        subscribeBtn.textContent = '訂閱通知';
    }
    subscribeBtn.disabled = false;
}

async function subscribe() {
    subscribeBtn.disabled = true;
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
        subscribeBtn.disabled = false;
    }
}

async function unsubscribe() {
    subscribeBtn.disabled = true;
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
        subscribeBtn.disabled = false;
    }
}

subscribeBtn.addEventListener('click', () => {
    if (isSubscribed) {
        unsubscribe();
    } else {
        subscribe();
    }
});

closeDetailBtn.addEventListener('click', closeDetail);
document.querySelector('.modal-backdrop')?.addEventListener('click', closeDetail);

function closeDetail() {
    detailModal.classList.remove('active');
    history.replaceState(null, '', window.location.pathname);
}

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
        
        if (data.detail) {
            detailContent.textContent = data.detail;
            detailContent.classList.remove('empty');
        } else {
            detailContent.textContent = '';
            detailContent.classList.add('empty');
        }
        
        detailTime.textContent = new Date(data.createdAt).toLocaleString('zh-TW');

        detailModal.classList.add('active');
        history.pushState(null, '', `?notification=${id}`);
    } catch (err) {
        console.error('Load detail failed:', err);
    }
}

async function loadNotificationHistory() {
    try {
        const response = await fetch('/api/notifications');
        allNotifications = await response.json();

        updateStats();
        renderRecentList();
        renderFullList();
    } catch (err) {
        console.error('Load history failed:', err);
    }
}

function updateStats() {
    statTotal.textContent = allNotifications.length;
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayCount = allNotifications.filter(n => new Date(n.createdAt) >= today).length;
    statToday.textContent = todayCount;
}

function renderRecentList() {
    const recent = allNotifications.slice(0, 3);
    
    if (recent.length === 0) {
        recentList.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                    <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                </svg>
                <p>尚無通知</p>
            </div>
        `;
        return;
    }
    
    recentList.innerHTML = recent.map(n => createNotificationItem(n)).join('');
    bindNotificationClicks(recentList);
}

function renderFullList() {
    if (allNotifications.length === 0) {
        notificationList.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                    <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                </svg>
                <p>尚無通知記錄</p>
            </div>
        `;
        return;
    }
    
    notificationList.innerHTML = allNotifications.map(n => createNotificationItem(n)).join('');
    bindNotificationClicks(notificationList);
}

function createNotificationItem(n) {
    const badge = n.detail ? '<span class="badge">有詳情</span>' : '';
    return `
        <div class="notification-item" data-id="${n.id}">
            <h4>${escapeHtml(n.title)}${badge}</h4>
            <p>${escapeHtml(n.body)}</p>
            <time>${formatTime(n.createdAt)}</time>
        </div>
    `;
}

function bindNotificationClicks(container) {
    container.querySelectorAll('.notification-item').forEach(item => {
        item.addEventListener('click', () => {
            showNotificationDetail(item.dataset.id);
        });
    });
}

function formatTime(dateStr) {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return '剛剛';
    if (diff < 3600000) return Math.floor(diff / 60000) + ' 分鐘前';
    if (diff < 86400000) return Math.floor(diff / 3600000) + ' 小時前';
    if (diff < 604800000) return Math.floor(diff / 86400000) + ' 天前';
    
    return date.toLocaleDateString('zh-TW');
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

window.addEventListener('popstate', () => {
    const params = new URLSearchParams(window.location.search);
    if (!params.get('notification')) {
        detailModal.classList.remove('active');
    }
});

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data.type === 'NOTIFICATION_CLICK') {
            showNotificationDetail(event.data.notificationId);
            loadNotificationHistory();
        }
    });
}

init();
