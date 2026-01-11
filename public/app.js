const subscribeBtn = document.getElementById('subscribeBtn');
const statusBadge = document.getElementById('statusBadge');
const statusText = document.getElementById('statusText');
const detailModal = document.getElementById('detailModal');
const detailTitle = document.getElementById('detailTitle');
const detailBody = document.getElementById('detailBody');
const detailContent = document.getElementById('detailContent');
const detailTime = document.getElementById('detailTime');
const detailChannel = document.getElementById('detailChannel');
const detailRecipient = document.getElementById('detailRecipient');
const closeDetailBtn = document.getElementById('closeDetailBtn');
const detailModalContent = document.querySelector('.detail-modal .modal-content');
const notificationList = document.getElementById('notificationList');
const recentList = document.getElementById('recentList');
const statTotal = document.getElementById('statTotal');
const statToday = document.getElementById('statToday');
const authBtn = document.getElementById('authBtn');
const authBadge = document.getElementById('authBadge');
const authDebug = document.getElementById('authDebug');
const sendLockOverlay = document.getElementById('sendLockOverlay');
const sendLockMessage = document.getElementById('sendLockMessage');

const sendForm = document.getElementById('sendForm');
const apiKeyInput = document.getElementById('apiKeyInput');
const detailCount = document.getElementById('detailCount');
const toggleApiKey = document.getElementById('toggleApiKey');
const sendResult = document.getElementById('sendResult');
const sendBtn = document.getElementById('sendBtn');
const userChannelSelect = document.getElementById('userChannelSelect');
const userIdentityDisplay = document.getElementById('userIdentityDisplay');
const channelSelectHint = document.getElementById('channelSelectHint');
const joinChannelInput = document.getElementById('joinChannelInput');
const joinPasscodeInput = document.getElementById('joinPasscodeInput');
const joinChannelBtn = document.getElementById('joinChannelBtn');
const joinChannelStatus = document.getElementById('joinChannelStatus');
const joinChannelHint = document.getElementById('joinChannelHint');
const tabItems = Array.from(document.querySelectorAll('.tab-item'));
const tabPanes = {
    home: document.getElementById('homePane'),
    history: document.getElementById('historyPane'),
    send: document.getElementById('sendPane')
};
const sendTabItem = tabItems.find(item => item.dataset.tab === 'send');
const channelSelect = document.getElementById('channelSelect');
const userChannelCustomWrap = document.getElementById('channelCustomWrap');
const userChannelCustomInput = document.getElementById('channelCustomInput');
const userRecipientInput = document.getElementById('recipientTargetInput');

let swRegistration = null;
let isSubscribed = false;
let allNotifications = [];
let activeTab = 'home';
let currentMode = null;
let resizeDebounce = null;
let touchStartX = 0;
let touchStartY = 0;
let touchDeltaX = 0;
let isTouchTracking = false;
let detailTouchStartX = 0;
let detailTouchStartY = 0;
let isDetailTouchTracking = false;

const MODE_BREAKPOINT = 900;
const PRESET_CHANNELS = ['global', 'ops', 'alpha'];
const STORAGE_KEYS = {
    apiKey: 'oyodo_api_key',
    userChannel: 'oyodo_user_channel'
};
const APP_ORIGIN = window.location.origin.replace(/\/$/, '');
const AUTH_CONFIG = {
    issuer: 'https://auth.baiyun.cv',
    clientId: '354957630411702491',
    redirectUri: `${APP_ORIGIN}/auth/callback`,
    logoutRedirectUri: APP_ORIGIN,
    scopes: 'openid profile email urn:zitadel:iam:org:project:roles'
};
const AUTH_STORAGE_KEYS = {
    tokens: 'oyodo_auth_tokens',
    pkce: 'oyodo_pkce_params'
};
const ROLE_PRIORITY = ['admin', 'moderator', 'subscriber'];
const ROLE_LABELS = {
    admin: '管理員',
    moderator: '版主',
    subscriber: '訂閱者'
};
const RANDOM_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

let authState = {
    isAuthenticated: false,
    user: null,
    roles: [],
    tokens: null
};
let subscriptionOptions = ['global'];

function getAccessToken() {
    return authState.tokens?.accessToken || null;
}

function getCurrentRecipientId() {
    return authState.user?.id || null;
}

function normalizeRoleName(role) {
    if (role === null || role === undefined) return '';
    if (typeof role === 'string') return role.trim().toLowerCase();
    return String(role).trim().toLowerCase();
}

function hasRole(role) {
    const target = normalizeRoleName(role);
    if (!target) return false;
    return (authState.roles || []).some(r => normalizeRoleName(r) === target);
}

function canSendNotifications() {
    return authState.isAuthenticated && (hasRole('admin') || hasRole('moderator'));
}

function canManageSubscriptions() {
    return authState.isAuthenticated && (hasRole('admin') || hasRole('moderator'));
}

function formatChannelLabel(channel) {
    if (!channel) return '';
    if (channel === 'global') return 'GLOBAL // 全域';
    return `${channel.toUpperCase()} // 專屬頻道`;
}

function setSubscriptionOptions(channels = []) {
    if (!userChannelSelect) return;
    const normalized = Array.from(
        new Set(
            (channels || [])
                .map(ch => normalizeChannelInput(ch))
                .filter(Boolean)
        )
    );
    if (!normalized.includes('global')) {
        normalized.unshift('global');
    }
    subscriptionOptions = normalized;
    const previous = getUserChannel();
    userChannelSelect.innerHTML = normalized
        .map(ch => `<option value="${ch}">${formatChannelLabel(ch)}</option>`)
        .join('');
    if (normalized.includes(previous)) {
        userChannelSelect.value = previous;
    } else {
        userChannelSelect.value = 'global';
        saveUserPreferences();
    }
}

function setUserIdentityDisplay() {
    if (!userIdentityDisplay) return;
    if (authState.isAuthenticated) {
        const id = authState.user?.id || '未知 ID';
        const name = authState.user?.displayName || authState.user?.email || '';
        userIdentityDisplay.textContent = name ? `${name}｜${id}` : `使用者｜${id}`;
    } else {
        userIdentityDisplay.textContent = '未登入｜訪客裝置';
    }
}

function setJoinControlsEnabled(enabled) {
    if (!joinChannelInput || !joinPasscodeInput || !joinChannelBtn) return;
    if (enabled) {
        joinChannelInput.removeAttribute('disabled');
        joinPasscodeInput.removeAttribute('disabled');
        joinChannelBtn.removeAttribute('disabled');
        joinChannelInput.classList.remove('input-disabled');
        joinPasscodeInput.classList.remove('input-disabled');
        joinChannelHint.textContent = '輸入頻道名稱與 6 位密碼即可加入。';
    } else {
        joinChannelInput.value = '';
        joinPasscodeInput.value = '';
        joinChannelInput.setAttribute('disabled', 'disabled');
        joinPasscodeInput.setAttribute('disabled', 'disabled');
        joinChannelBtn.setAttribute('disabled', 'disabled');
        joinChannelInput.classList.add('input-disabled');
        joinPasscodeInput.classList.add('input-disabled');
        joinChannelHint.textContent = '登入後即可加入專屬頻道。';
    }
}

function setJoinStatus(type, message) {
    if (!joinChannelStatus) return;
    if (!message) {
        joinChannelStatus.hidden = true;
        joinChannelStatus.textContent = '';
        joinChannelStatus.className = 'join-status';
        return;
    }
    joinChannelStatus.hidden = false;
    joinChannelStatus.textContent = message;
    joinChannelStatus.className = `join-status ${type}`;
}

function getUserChannel() {
    return normalizeChannelInput(userChannelSelect?.value) || 'global';
}

function getSelectedSubscriptionChannel() {
    return getUserChannel();
}

async function authFetch(url, options = {}) {
    const token = getAccessToken();
    if (!token) {
        throw new Error('尚未登入');
    }
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    return fetch(url, {
        ...options,
        headers
    });
}

async function refreshUserChannels() {
    if (!userChannelSelect) return;
    if (!authState.isAuthenticated) {
        setSubscriptionOptions(['global']);
        setUserIdentityDisplay();
        setJoinControlsEnabled(false);
        setJoinStatus();
        return;
    }
    setJoinControlsEnabled(true);
    setUserIdentityDisplay();
    const token = getAccessToken();
    if (!token) {
        setSubscriptionOptions(['global']);
        return;
    }
    try {
        const response = await fetch('/api/channels/mine', {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        if (!response.ok) {
            throw new Error('無法載入頻道列表');
        }
        const data = await response.json();
        const channels = Array.isArray(data.channels) ? data.channels : [];
        setSubscriptionOptions(['global', ...channels]);
        setJoinStatus();
    } catch (err) {
        console.error('Load channels failed:', err);
        setSubscriptionOptions(['global']);
        setJoinStatus('error', '無法同步頻道');
    }
}

async function handleJoinChannel() {
    if (!authState.isAuthenticated) {
        setJoinStatus('error', '請先登入後再加入頻道');
        return;
    }
    if (!joinChannelInput || !joinPasscodeInput || !joinChannelBtn) return;
    const channel = normalizeChannelInput(joinChannelInput.value);
    const passcode = (joinPasscodeInput.value || '').trim();
    if (!channel || channel === 'global') {
        setJoinStatus('error', '請輸入有效的頻道名稱');
        joinChannelInput.focus();
        return;
    }
    if (!/^\d{6}$/.test(passcode)) {
        setJoinStatus('error', '密碼需為 6 位數字');
        joinPasscodeInput.focus();
        return;
    }
    joinChannelBtn.disabled = true;
    joinChannelBtn.dataset.loading = 'true';
    setJoinStatus('info', '驗證中...');
    try {
        const response = await authFetch('/api/channels/join', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ channel, passcode })
        });
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            const status = response.status;
            const error = data.error || '加入失敗';
            if (status === 404) {
                setJoinStatus('error', `找不到頻道 #${channel}`);
                return;
            }
            if (status === 403) {
                setJoinStatus('error', '密碼不正確，請再試一次');
                return;
            }
            throw new Error(error);
        }

        setJoinStatus('success', `已加入 #${channel}`);
        joinChannelInput.value = '';
        joinPasscodeInput.value = '';
        await refreshUserChannels();
    } catch (err) {
        console.error('Join channel failed:', err);
        setJoinStatus('error', err.message || '加入失敗');
    } finally {
        joinChannelBtn.disabled = false;
        delete joinChannelBtn.dataset.loading;
    }
}

function generateRandomString(length = 64) {
    const array = new Uint32Array(length);
    if (!window.crypto?.getRandomValues) {
        throw new Error('此瀏覽器不支援安全隨機數，請改用支援的環境');
    }
    window.crypto.getRandomValues(array);
    return Array.from(array, value => RANDOM_CHARSET[value % RANDOM_CHARSET.length]).join('');
}

function base64UrlEncode(buffer) {
    let bytes;
    if (buffer instanceof ArrayBuffer) {
        bytes = new Uint8Array(buffer);
    } else if (buffer instanceof Uint8Array) {
        bytes = buffer;
    } else {
        bytes = new TextEncoder().encode(buffer);
    }
    let binary = '';
    bytes.forEach(b => {
        binary += String.fromCharCode(b);
    });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64Url(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(digest);
}

function savePkceParams(params) {
    sessionStorage.setItem(AUTH_STORAGE_KEYS.pkce, JSON.stringify(params));
}

function loadPkceParams() {
    const raw = sessionStorage.getItem(AUTH_STORAGE_KEYS.pkce);
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (err) {
        console.error('PKCE params parse failed:', err);
        sessionStorage.removeItem(AUTH_STORAGE_KEYS.pkce);
        return null;
    }
}

function clearPkceParams() {
    sessionStorage.removeItem(AUTH_STORAGE_KEYS.pkce);
}

function saveAuthTokens(tokenResponse) {
    const expiresIn = tokenResponse.expires_in || 0;
    const stored = {
        accessToken: tokenResponse.access_token,
        idToken: tokenResponse.id_token,
        refreshToken: tokenResponse.refresh_token || null,
        tokenType: tokenResponse.token_type,
        scope: tokenResponse.scope,
        expiresAt: Date.now() + expiresIn * 1000
    };
    sessionStorage.setItem(AUTH_STORAGE_KEYS.tokens, JSON.stringify(stored));
    return stored;
}

function loadAuthTokens() {
    const raw = sessionStorage.getItem(AUTH_STORAGE_KEYS.tokens);
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (err) {
        console.error('Token parse failed:', err);
        sessionStorage.removeItem(AUTH_STORAGE_KEYS.tokens);
        return null;
    }
}

function clearAuthTokens() {
    sessionStorage.removeItem(AUTH_STORAGE_KEYS.tokens);
}

function decodeJwtPayload(token) {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
    try {
        const json = atob(padded);
        return JSON.parse(json);
    } catch (err) {
        console.error('Failed to decode JWT payload:', err);
        return null;
    }
}

function extractRolesFromPayload(payload) {
    if (!payload) return [];
    const raw = payload['urn:zitadel:iam:org:project:roles'];
    if (!raw) return [];

    const collected = new Set();
    const pushRole = role => {
        const normalized = normalizeRoleName(role);
        if (normalized) collected.add(normalized);
    };

    const processValue = value => {
        if (!value) return;
        if (Array.isArray(value)) {
            value.forEach(processValue);
            return;
        }
        if (typeof value === 'string') {
            pushRole(value);
            return;
        }
        if (value === true || value === 1 || value === 'true') {
            return;
        }
        if (typeof value === 'object') {
            Object.entries(value).forEach(([key, nested]) => {
                if (nested === true || nested === 1 || nested === 'true') {
                    pushRole(key);
                } else {
                    processValue(nested);
                }
            });
        }
    };

    if (Array.isArray(raw) || typeof raw === 'string') {
        processValue(raw);
    } else if (typeof raw === 'object') {
        Object.values(raw).forEach(processValue);
    }

    return Array.from(collected);
}

function getPrimaryRole(roles = []) {
    for (const role of ROLE_PRIORITY) {
        if (roles.includes(role)) return role;
    }
    return roles[0] || null;
}

function updateAuthStateFromTokens(tokenSet) {
    const payload = decodeJwtPayload(tokenSet?.idToken);
    if (!payload) return;
    const roles = extractRolesFromPayload(payload);
    authState = {
        isAuthenticated: true,
        user: {
            displayName: payload.name || payload.preferred_username || payload.email || '已登入',
            email: payload.email || null,
            id: payload.sub || null
        },
        roles,
        tokens: tokenSet
    };
    applyAuthState();
}

function applyAuthState() {
    if (authBtn) {
        if (authState.isAuthenticated) {
            authBtn.textContent = '登出';
        } else {
            authBtn.textContent = '登入系統';
        }
    }
    setUserIdentityDisplay();
    if (authBadge) {
        if (authState.isAuthenticated) {
            const primaryRole = getPrimaryRole(authState.roles);
            const roleLabel = ROLE_LABELS[primaryRole] || '登入中';
            const name = authState.user?.displayName || authState.user?.email || '';
            authBadge.textContent = name ? `${roleLabel}｜${name}` : roleLabel;
            authBadge.hidden = false;
        } else {
            authBadge.hidden = true;
            authBadge.textContent = '';
        }
    }
    if (authDebug) {
        if (authState.isAuthenticated) {
            const scope = authState.roles?.join(', ') || 'none';
            const sendAllowed = canSendNotifications();
            authDebug.textContent = `roles: [${scope}] • canSend: ${sendAllowed}`;
            authDebug.hidden = false;
        } else {
            authDebug.hidden = true;
            authDebug.textContent = '';
        }
    }
    updateAccessControls();
}

function restoreAuthSession() {
    const stored = loadAuthTokens();
    if (!stored) {
        applyAuthState();
        return;
    }
    if (stored.expiresAt && stored.expiresAt <= Date.now()) {
        clearAuthTokens();
        applyAuthState();
        return;
    }
    updateAuthStateFromTokens(stored);
}

async function beginLogin() {
    try {
        const codeVerifier = generateRandomString(96);
        const state = generateRandomString(32);
        const codeChallenge = await sha256Base64Url(codeVerifier);
        savePkceParams({ codeVerifier, state, createdAt: Date.now() });

        const authorizeUrl = new URL(`${AUTH_CONFIG.issuer}/oauth/v2/authorize`);
        authorizeUrl.searchParams.set('client_id', AUTH_CONFIG.clientId);
        authorizeUrl.searchParams.set('response_type', 'code');
        authorizeUrl.searchParams.set('redirect_uri', AUTH_CONFIG.redirectUri);
        authorizeUrl.searchParams.set('scope', AUTH_CONFIG.scopes);
        authorizeUrl.searchParams.set('state', state);
        authorizeUrl.searchParams.set('code_challenge', codeChallenge);
        authorizeUrl.searchParams.set('code_challenge_method', 'S256');

        window.location.href = authorizeUrl.toString();
    } catch (err) {
        console.error('Auth init failed:', err);
        alert('無法啟動登入流程，請稍後再試');
    }
}

function isAuthCallbackRoute() {
    return window.location.pathname.startsWith('/auth/callback');
}

async function handleAuthRedirect() {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    if (error) {
        alert('登入失敗：' + (params.get('error_description') || error));
        window.location.replace('/');
        return;
    }

    const code = params.get('code');
    const state = params.get('state');
    const pkce = loadPkceParams();
    clearPkceParams();

    if (!code || !state || !pkce || state !== pkce.state) {
        alert('登入驗證失敗，請重新登入');
        window.location.replace('/');
        return;
    }

    try {
        const tokenResponse = await exchangeCodeForTokens(code, pkce.codeVerifier);
        saveAuthTokens(tokenResponse);
    } catch (err) {
        console.error('Token exchange failed:', err);
        alert('無法完成登入流程，請稍後再試');
    } finally {
        window.location.replace('/');
    }
}

async function exchangeCodeForTokens(code, codeVerifier) {
    const body = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: AUTH_CONFIG.clientId,
        code,
        redirect_uri: AUTH_CONFIG.redirectUri,
        code_verifier: codeVerifier
    });

    const response = await fetch(`${AUTH_CONFIG.issuer}/oauth/v2/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token endpoint error: ${errorText}`);
    }

    return response.json();
}

function logout() {
    const storedTokens = authState.tokens || loadAuthTokens();
    const idTokenHint = storedTokens?.idToken || null;

    clearAuthTokens();
    authState = {
        isAuthenticated: false,
        user: null,
        roles: [],
        tokens: null
    };
    applyAuthState();

    const logoutUrl = new URL(`${AUTH_CONFIG.issuer}/oidc/v1/end_session`);
    logoutUrl.searchParams.set('client_id', AUTH_CONFIG.clientId);
    logoutUrl.searchParams.set('post_logout_redirect_uri', AUTH_CONFIG.logoutRedirectUri);
    if (idTokenHint) {
        logoutUrl.searchParams.set('id_token_hint', idTokenHint);
    }
    window.location.replace(logoutUrl.toString());
}

function updateAccessControls() {
    updateSendPanelAccess();
    updateSubscriptionAccess();
}

function updateSendPanelAccess() {
    if (!sendForm || !sendLockOverlay || !sendLockMessage) return;
    const allowed = canSendNotifications();
    if (allowed) {
        sendLockOverlay.hidden = true;
        setFormDisabled(sendForm, false);
        return;
    }
    const message = authState.isAuthenticated
        ? '需要版主以上權限才能發送訊息'
        : '請登入後使用廣播功能';
    sendLockMessage.textContent = message;
    sendLockOverlay.hidden = false;
    setFormDisabled(sendForm, true);
}

function setFormDisabled(form, disabled) {
    if (!form) return;
    form.querySelectorAll('input, textarea, select, button').forEach(el => {
        el.disabled = disabled;
    });
    form.classList.toggle('form-disabled', disabled);
}

function updateSubscriptionAccess() {
    if (!userChannelSelect) return;
    const allowCustomChannel = canManageSubscriptions();
    if (allowCustomChannel) {
        userChannelSelect.disabled = false;
        if (userChannelCustomInput) userChannelCustomInput.disabled = false;
        return;
    }
    userChannelSelect.value = 'global';
    userChannelSelect.disabled = true;
    if (userChannelCustomInput) {
        userChannelCustomInput.value = '';
        userChannelCustomInput.disabled = true;
    }
    if (userChannelCustomWrap) {
        userChannelCustomWrap.classList.remove('active');
    }
    applyChannelSelection(
        userChannelSelect,
        userChannelCustomInput,
        userChannelCustomWrap,
        'global',
        'global'
    );
    saveUserPreferences();
}

function normalizeChannelInput(value) {
    return (value || '').trim().toLowerCase();
}

function getChannelValue(selectEl, customInput, fallback = '') {
    if (!selectEl) return fallback;
    if (selectEl.value === '__custom') {
        const customVal = normalizeChannelInput(customInput?.value);
        return customVal || fallback;
    }
    const normalized = normalizeChannelInput(selectEl.value);
    return normalized || fallback;
}

function applyChannelSelection(selectEl, customInput, wrapEl, value, fallback = '') {
    if (!selectEl) return;
    const normalized = normalizeChannelInput(value) || normalizeChannelInput(fallback);
    if (normalized && PRESET_CHANNELS.includes(normalized)) {
        selectEl.value = normalized;
        if (customInput) customInput.value = '';
    } else if (normalized) {
        selectEl.value = '__custom';
        if (customInput) customInput.value = normalized;
    } else {
        selectEl.value = '';
        if (customInput) customInput.value = '';
    }
    updateCustomChannelVisibility(selectEl, wrapEl);
}

function updateCustomChannelVisibility(selectEl, wrapEl) {
    if (!wrapEl) return;
    if (selectEl?.value === '__custom') {
        wrapEl.classList.add('active');
    } else {
        wrapEl.classList.remove('active');
    }
}

function getUserChannel() {
    return getChannelValue(userChannelSelect, userChannelCustomInput, 'global') || 'global';
}

function saveUserPreferences() {
    const channel = getUserChannel();
    localStorage.setItem(STORAGE_KEYS.userChannel, channel);
    if (userRecipientInput) {
        const recipient = userRecipientInput.value.trim();
        if (recipient) {
            localStorage.setItem(STORAGE_KEYS.userRecipient, recipient);
        } else {
            localStorage.removeItem(STORAGE_KEYS.userRecipient);
        }
    }
}

async function init() {
    initTabs();
    initSendForm();
    initSubscriptionControls();
    initGestures();
    initDetailGestures();
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

function injectPendingNotification({ title, body, detail, channel, recipientId }) {
    const tempNotification = {
        id: `temp-${Date.now()}`,
        title,
        body,
        detail,
        channel: channel || null,
        recipientId: recipientId || null,
        createdAt: new Date().toISOString(),
        _temp: true
    };
    allNotifications = [tempNotification, ...allNotifications];
    updateStats();
    renderRecentList();
    renderFullList();
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
    const savedApiKey = localStorage.getItem(STORAGE_KEYS.apiKey);
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

    if (channelSelect) {
        updateCustomChannelVisibility(channelSelect, channelCustomWrap);
        channelSelect.addEventListener('change', () => {
            updateCustomChannelVisibility(channelSelect, channelCustomWrap);
            if (channelSelect.value !== '__custom' && channelCustomInput) {
                channelCustomInput.value = '';
            }
        });
    }

    channelCustomInput?.addEventListener('blur', () => {
        channelCustomInput.value = normalizeChannelInput(channelCustomInput.value);
    });

    recipientTargetInput?.addEventListener('blur', () => {
        if (!recipientTargetInput) return;
        recipientTargetInput.value = recipientTargetInput.value.trim();
    });
    
    sendForm.addEventListener('submit', handleSendNotification);
}

function initSubscriptionControls() {
    if (!userChannelSelect) return;

    const savedChannel = localStorage.getItem(STORAGE_KEYS.userChannel) || 'global';
    applyChannelSelection(
        userChannelSelect,
        userChannelCustomInput,
        userChannelCustomWrap,
        savedChannel,
        'global'
    );
    updateCustomChannelVisibility(userChannelSelect, userChannelCustomWrap);

    const savedRecipient = localStorage.getItem(STORAGE_KEYS.userRecipient) || '';
    if (userRecipientInput && savedRecipient) {
        userRecipientInput.value = savedRecipient;
    }

    userChannelSelect.addEventListener('change', () => {
        updateCustomChannelVisibility(userChannelSelect, userChannelCustomWrap);
        saveUserPreferences();
    });

    userChannelCustomInput?.addEventListener('input', () => {
        if (userChannelSelect.value === '__custom') {
            saveUserPreferences();
        }
    });
    userChannelCustomInput?.addEventListener('blur', () => {
        if (userChannelSelect.value === '__custom') {
            userChannelCustomInput.value = normalizeChannelInput(userChannelCustomInput.value);
            saveUserPreferences();
        }
    });

    userRecipientInput?.addEventListener('input', () => {
        saveUserPreferences();
    });
    userRecipientInput?.addEventListener('blur', () => {
        userRecipientInput.value = userRecipientInput.value.trim();
        saveUserPreferences();
    });

    updateSubscriptionAccess();
}

async function handleSendNotification(e) {
    e.preventDefault();

    if (!canSendNotifications()) {
        showSendResult('error', '你沒有權限發送訊息');
        return;
    }
    
    const apiKey = apiKeyInput.value.trim();
    const title = titleInput.value.trim();
    const body = bodyInput.value.trim();
    const detail = detailInput.value.trim();
    const selectedChannel = getChannelValue(channelSelect, channelCustomInput, '');
    const targetRecipient = recipientTargetInput?.value.trim();
    
    if (!apiKey) {
        showSendResult('error', '請輸入 API 金鑰');
        return;
    }
    
    if (!title || !body) {
        showSendResult('error', '標題和內文為必填');
        return;
    }

    if (channelSelect?.value === '__custom' && !selectedChannel) {
        showSendResult('error', '請輸入自訂頻道名稱');
        channelCustomInput?.focus();
        return;
    }
    
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span>廣播中...</span>';
    
    try {
        localStorage.setItem(STORAGE_KEYS.apiKey, apiKey);
        
        const payload = {
            title,
            body,
            detail: detail || undefined
        };
        if (selectedChannel) {
            payload.channel = selectedChannel;
        }
        if (targetRecipient) {
            payload.recipientId = targetRecipient;
        }
        
        const response = await fetch('/api/notify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': apiKey
            },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || '發送失敗');
        }
        
        showSendResult('success', `發送成功！已送達 ${data.delivered} 位訂閱者`);
        injectPendingNotification({ title, body, detail, channel: selectedChannel, recipientId: targetRecipient });
        titleInput.value = '';
        bodyInput.value = '';
        detailInput.value = '';
        if (channelSelect && channelSelect.value !== '__custom') {
            channelCustomInput && (channelCustomInput.value = '');
        }
        if (recipientTargetInput) {
            recipientTargetInput.value = '';
        }
        titleCount.textContent = '0';
        bodyCount.textContent = '0';
        detailCount.textContent = '0';
        
        await loadNotificationHistory();
    } catch (err) {
        console.error('Send failed:', err);
        showSendResult('error', err.message);
    } finally {
        sendBtn.disabled = false;
        sendBtn.innerHTML = '執行廣播';
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

function initGestures() {
    const surface = document.querySelector('.tab-content');
    if (!surface) return;

    surface.addEventListener('touchstart', handleTouchStart, { passive: true });
    surface.addEventListener('touchmove', handleTouchMove, { passive: false });
    surface.addEventListener('touchend', handleTouchEnd);
}

function initDetailGestures() {
    if (!detailModalContent) return;
    detailModalContent.addEventListener('touchstart', handleDetailTouchStart, { passive: true });
    detailModalContent.addEventListener('touchmove', handleDetailTouchMove, { passive: false });
    detailModalContent.addEventListener('touchend', handleDetailTouchEnd);
}

function handleTouchStart(event) {
    if (event.touches.length !== 1 || detailModal?.classList.contains('active')) return;
    const touch = event.touches[0];
    touchStartX = touch.clientX;
    touchStartY = touch.clientY;
    touchDeltaX = 0;
    isTouchTracking = true;
}

function handleTouchMove(event) {
    if (!isTouchTracking || event.touches.length !== 1) return;
    const touch = event.touches[0];
    const deltaX = touch.clientX - touchStartX;
    const deltaY = touch.clientY - touchStartY;

    if (Math.abs(deltaY) > Math.abs(deltaX)) {
        isTouchTracking = false;
        return;
    }

    touchDeltaX = deltaX;
    if (Math.abs(deltaX) > 10) {
        event.preventDefault();
    }
}

function handleTouchEnd(event) {
    if (!isTouchTracking) return;
    isTouchTracking = false;

    const deltaX = event.changedTouches[0].clientX - touchStartX;
    if (Math.abs(deltaX) < 60) return;

    if (deltaX < 0) {
        goToAdjacentTab('next');
    } else {
        goToAdjacentTab('prev');
    }
}

function handleDetailTouchStart(event) {
    if (!detailModal?.classList.contains('active') || event.touches.length !== 1) return;
    const touch = event.touches[0];
    detailTouchStartX = touch.clientX;
    detailTouchStartY = touch.clientY;
    isDetailTouchTracking = true;
}

function handleDetailTouchMove(event) {
    if (!isDetailTouchTracking || event.touches.length !== 1) return;
    const touch = event.touches[0];
    const deltaX = touch.clientX - detailTouchStartX;
    const deltaY = touch.clientY - detailTouchStartY;

    if (Math.abs(deltaY) > Math.abs(deltaX)) {
        isDetailTouchTracking = false;
        return;
    }

    if (deltaX > 10) {
        event.preventDefault();
    }
}

function handleDetailTouchEnd(event) {
    if (!isDetailTouchTracking) return;
    isDetailTouchTracking = false;

    const deltaX = event.changedTouches[0].clientX - detailTouchStartX;
    if (deltaX > 80) {
        closeDetail();
    }
}

function goToAdjacentTab(direction) {
    const visibleTabs = tabItems.filter(item => !item.classList.contains('tab-item--hidden'));
    const currentIndex = visibleTabs.findIndex(item => item.dataset.tab === activeTab);
    if (currentIndex === -1) return;

    if (direction === 'next' && currentIndex < visibleTabs.length - 1) {
        activateTab(visibleTabs[currentIndex + 1].dataset.tab);
    } else if (direction === 'prev' && currentIndex > 0) {
        activateTab(visibleTabs[currentIndex - 1].dataset.tab);
    }
}

async function subscribe() {
    subscribeBtn.disabled = true;
    try {
        saveUserPreferences();
        const response = await fetch('/api/vapid-public-key');
        const { publicKey } = await response.json();

        const subscription = await swRegistration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey)
        });

        const recipientPref = userRecipientInput ? userRecipientInput.value.trim() : '';
        const payload = {
            subscription,
            channel: getUserChannel()
        };
        if (recipientPref) {
            payload.recipientId = recipientPref;
        }

        await fetch('/api/subscribe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
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
        setPillContent(detailChannel, data.channel, value => `#${value}`);
        setPillContent(detailRecipient, data.recipientId, value => `@${value}`);

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
    const channelPill = n.channel ? `<span class="pill channel-pill">#${escapeHtml(n.channel)}</span>` : '';
    const recipientPill = n.recipientId ? `<span class="pill recipient-pill">@${escapeHtml(n.recipientId)}</span>` : '';
    const metaRow = channelPill || recipientPill ? `<div class="notification-meta">${channelPill}${recipientPill}</div>` : '';
    return `
        <div class="notification-item" data-id="${n.id}">
            <h4>${escapeHtml(n.title)}${badge}</h4>
            ${metaRow}
            <p>${escapeHtml(n.body)}</p>
            <time>${formatTime(n.createdAt)}</time>
        </div>
    `;
}

function setPillContent(element, value, formatter = v => v) {
    if (!element) return;
    if (value) {
        element.hidden = false;
        element.textContent = formatter(value);
    } else {
        element.hidden = true;
        element.textContent = '';
    }
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

function setupAuthControls() {
    authBtn?.addEventListener('click', () => {
        if (authState.isAuthenticated) {
            logout();
        } else {
            beginLogin();
        }
    });
}

function bootstrap() {
    if (isAuthCallbackRoute()) {
        handleAuthRedirect();
        return;
    }
    restoreAuthSession();
    setupAuthControls();
    init();
}

bootstrap();
