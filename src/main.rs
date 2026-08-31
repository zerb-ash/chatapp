use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use aes_gcm::aead::rand_core::RngCore;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const GLOBAL_PASSPHRASE: &str = "RUSTCORD_SERVER_GLOBAL_SECRET_KEY";
const GLOBAL_SALT: &[u8] = b"rust_cord_secure_salt_2026";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EncryptedMessage {
    username: String,
    ciphertext: String,
    iv: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
enum ServerEvent {
    JoinSuccess { username: String },
    JoinError { error: String },
    History { messages: Vec<EncryptedMessage> },
    Message { username: String, ciphertext: String, iv: String, timestamp: u64 },
    UserList { users: Vec<String> },
    Typing { username: String, is_typing: bool },
    VoiceSignal { from: String, target: String, signal: serde_json::Value },
    VoiceInvite { from: String, target: String, room_id: String },
    VoiceStateUpdate { username: String, room_id: Option<String> },
    DeleteVoiceRoom { room_id: String },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientEvent {
    Join { username: String },
    Send { text: String },
    Typing { is_typing: bool },
    VoiceSignal { target: String, signal: serde_json::Value },
    VoiceInvite { target: String, room_id: String },
    VoiceStateUpdate { room_id: Option<String> },
    DeleteVoiceRoom { room_id: String },
}

struct AppState {
    tx: broadcast::Sender<String>,
    users: Mutex<HashMap<usize, String>>,
    voice_states: Mutex<HashMap<String, String>>,
    messages: Mutex<VecDeque<EncryptedMessage>>,
    cipher: Aes256Gcm,
}

fn derive_global_cipher() -> Aes256Gcm {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        GLOBAL_PASSPHRASE.as_bytes(),
        GLOBAL_SALT,
        100_000,
        &mut key_bytes,
    );
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    Aes256Gcm::new(key)
}

#[tokio::main]
async fn main() {
    let cipher = derive_global_cipher();
    let (tx, _) = broadcast::channel::<String>(200);

    let state = Arc::new(AppState {
        tx,
        users: Mutex::new(HashMap::new()),
        voice_states: Mutex::new(HashMap::new()),
        messages: Mutex::new(VecDeque::new()),
        cipher,
    });

    let state_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut msgs = state_cleanup.messages.lock().unwrap();
            msgs.retain(|msg| now.saturating_sub(msg.timestamp) < 86400);
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/ws", get(move |ws| ws_handler(ws, state)));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RustCord</title>
        <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #313338; color: #dbdee1; display: flex; height: 100vh; overflow: hidden; }

            #sidebar { width: 260px; background: #2b2d31; display: flex; flex-direction: column; border-right: 1px solid #1f2023; }
            .sidebar-header { padding: 16px; font-weight: bold; color: #f2f5f7; border-bottom: 1px solid #1f2023; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }

            .vc-section { padding: 12px 8px; border-bottom: 1px solid #1f2023; overflow-y: auto; max-height: 40vh; }
            .vc-title { font-size: 11px; font-weight: bold; color: #949ba4; text-transform: uppercase; margin-bottom: 8px; padding-left: 8px; }
            .vc-item { display: flex; align-items: center; justify-content: space-between; padding: 8px; border-radius: 4px; color: #949ba4; cursor: pointer; font-size: 14px; margin-bottom: 2px; }
            .vc-item:hover { background: #35373c; color: #dbdee1; }
            .vc-item.active { background: #404249; color: #fff; }

            .vc-delete-btn { opacity: 0.6; cursor: pointer; padding: 2px 4px; border-radius: 3px; }
            .vc-delete-btn:hover { opacity: 1; background: #da373c; }

            .vc-roster { list-style: none; padding-left: 20px; margin-top: 4px; margin-bottom: 8px; }
            .vc-user { display: flex; align-items: center; gap: 8px; padding: 4px 8px; font-size: 13px; color: #949ba4; border-radius: 4px; }
            .vc-user-avatar { width: 24px; height: 24px; border-radius: 50%; background: #5865f2; color: #fff; font-size: 11px; font-weight: bold; display: flex; align-items: center; justify-content: center; border: 2px solid transparent; transition: border-color 0.15s ease; }
            .vc-user-avatar.speaking { border-color: #23a55a !important; box-shadow: 0 0 6px rgba(35, 165, 90, 0.8); }

            .vc-controls { display: flex; gap: 6px; padding: 10px; background: #232428; border-top: 1px solid #1f2023; }
            .vc-btn { flex: 1; padding: 8px 4px; background: #313338; border: none; border-radius: 4px; color: #dbdee1; font-size: 11px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 4px; }
            .vc-btn:hover:not(:disabled) { background: #383a40; }
            .vc-btn.active { background: #da373c; color: #fff; }
            .vc-btn:disabled { opacity: 0.4; cursor: not-allowed; }

            #user-list { list-style: none; padding: 10px; overflow-y: auto; flex: 1; }
            #user-list li { display: flex; align-items: center; justify-content: space-between; padding: 8px; border-radius: 4px; font-size: 14px; color: #949ba4; position: relative; }
            #user-list li:hover { background: #35373c; color: #dbdee1; }
            .user-info { display: flex; align-items: center; gap: 8px; }
            .status-dot { width: 8px; height: 8px; background: #23a55a; border-radius: 50%; display: inline-block; }
            .invite-btn { display: none; padding: 4px 8px; background: #5865f2; color: white; border: none; border-radius: 3px; font-size: 11px; font-weight: bold; cursor: pointer; }
            #user-list li:hover .invite-btn { display: block; }
            .invite-btn:hover { background: #4752c4; }

            #main { flex: 1; display: flex; flex-direction: column; background: #313338; position: relative; }
            .chat-header { padding: 16px; background: #313338; border-bottom: 1px solid #1f2023; font-weight: bold; color: #f2f5f7; display: flex; justify-content: space-between; align-items: center; }
            #messages { flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; }

            .msg-group { display: flex; gap: 16px; margin-top: 16px; width: 100%; }
            .msg-group.grouped { margin-top: 2px; }
            .avatar-col { width: 40px; display: flex; justify-content: center; flex-shrink: 0; }
            .avatar { width: 40px; height: 40px; border-radius: 50%; background: #5865f2; color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; }
            .hover-time { font-size: 10px; color: #949ba4; opacity: 0; width: 40px; text-align: right; line-height: 22px; user-select: none; }
            .msg-group:hover .hover-time { opacity: 1; }

            .msg-content { display: flex; flex-direction: column; flex: 1; overflow: hidden; }
            .msg-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
            .username { font-weight: 600; color: #f2f5f7; font-size: 15px; }
            .timestamp { font-size: 11px; color: #949ba4; }
            .body { color: #dbdee1; font-size: 14px; line-height: 1.4; word-break: break-word; }

            .body img, .body video { max-width: 400px; max-height: 300px; border-radius: 8px; margin-top: 8px; display: block; object-fit: contain; }
            .body a { color: #00a8fc; text-decoration: none; }
            .body code { background: #2b2d31; padding: 2px 4px; border-radius: 4px; font-family: monospace; }

            #video-grid { display: none; height: 260px; background: #111214; padding: 10px; gap: 10px; overflow-x: auto; border-bottom: 1px solid #1f2023; }
            #video-grid video { height: 100%; border-radius: 6px; background: #000; object-fit: contain; }

            .input-container { padding: 0 20px 20px 20px; position: relative; }

            #image-preview-container { display: none; background: #2b2d31; padding: 8px 12px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #383a40; align-items: center; gap: 12px; }
            #image-preview { height: 60px; max-width: 120px; border-radius: 4px; object-fit: cover; border: 1px solid #404249; }
            .remove-img-btn { background: #da373c; color: white; border: none; width: 20px; height: 20px; border-radius: 50%; cursor: pointer; font-size: 11px; display: flex; align-items: center; justify-content: center; font-weight: bold; }
            .remove-img-btn:hover { background: #a1282b; }

            .input-box { background: #383a40; border-radius: 8px; display: flex; align-items: center; padding: 0 16px; }
            .input-box.has-preview { border-top-left-radius: 0; border-top-right-radius: 0; }
            #message-input { width: 100%; background: transparent; border: none; padding: 14px 0; color: #dbdee1; font-size: 14px; outline: none; }
            #typing-indicator { position: absolute; top: -20px; left: 24px; font-size: 12px; color: #b5bac1; font-style: italic; min-height: 16px; }

            #modal { position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 100; }
            .modal-box { background: #313338; padding: 32px; border-radius: 8px; width: 360px; text-align: center; }
            .modal-box h3 { color: #f2f5f7; margin-bottom: 8px; }
            .modal-box p { color: #949ba4; font-size: 13px; margin-bottom: 16px; }
            .modal-box input { width: 100%; padding: 10px; background: #1e1f22; border: 1px solid #111214; border-radius: 4px; color: white; margin-bottom: 12px; outline: none; }
            .modal-box button { width: 100%; padding: 12px; background: #5865f2; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
            #error-msg { color: #f23f43; font-size: 13px; margin-bottom: 10px; display: none; }

            .toast-invite { position: fixed; bottom: 24px; right: 24px; background: #2b2d31; border: 1px solid #5865f2; border-radius: 8px; padding: 16px; width: 300px; z-index: 200; box-shadow: 0 8px 16px rgba(0,0,0,0.4); display: none; }
            .toast-invite h4 { color: #fff; margin-bottom: 6px; font-size: 14px; }
            .toast-invite p { color: #949ba4; font-size: 12px; margin-bottom: 12px; }
            .toast-btns { display: flex; gap: 8px; }
            .toast-btns button { flex: 1; padding: 8px; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 12px; }
            .btn-accept { background: #23a55a; color: white; }
            .btn-decline { background: #da373c; color: white; }

            #remote-audio-container { display: none; }
        </style>
    </head>
    <body>

        <div id="remote-audio-container"></div>

        <div id="modal">
            <div class="modal-box">
                <h3>Welcome to RustCord</h3>
                <p>Enter a username to join the server.</p>
                <div id="error-msg"></div>
                <input id="username-input" type="text" placeholder="Username" autofocus />
                <button onclick="attemptJoin()">Join Server</button>
            </div>
        </div>

        <div id="toast" class="toast-invite">
            <h4 id="toast-title">Voice Invite</h4>
            <p id="toast-body">Someone invited you to a private VC.</p>
            <div class="toast-btns">
                <button class="btn-accept" onclick="acceptInvite()">Join VC</button>
                <button class="btn-decline" onclick="declineInvite()">Decline</button>
            </div>
        </div>

        <div id="sidebar">
            <div class="sidebar-header">Channels & Voice</div>

            <div class="vc-section">
                <div class="vc-title">Voice Channels</div>
                <div id="vc-general" class="vc-item" onclick="toggleVoiceChannel('general')">
                    <span>🔊 General VC</span>
                </div>
                <ul id="roster-general" class="vc-roster"></ul>

                <div id="private-rooms-list"></div>
            </div>

            <div class="sidebar-header" style="border-top: 1px solid #1f2023;">Online Users — <span id="user-count">0</span></div>
            <ul id="user-list"></ul>

            <div class="vc-controls">
                <button id="btn-mute" class="vc-btn" onclick="toggleMute()">🎙️ Mute</button>
                <button id="btn-deaf" class="vc-btn" onclick="toggleDeafen()">🎧 Deafen</button>
                <button id="btn-screen" class="vc-btn" onclick="toggleScreenShare()" disabled title="Screen sharing enabled inside voice rooms">🖥️ Share</button>
            </div>
        </div>

        <div id="main">
            <div class="chat-header">
                <span id="channel-title"># general</span>
            </div>

            <div id="video-grid"></div>
            <div id="messages"></div>

            <div class="input-container">
                <div id="typing-indicator"></div>

                <div id="image-preview-container">
                    <img id="image-preview" src="" alt="Pasted Image Preview" />
                    <button class="remove-img-btn" onclick="clearPastedImage()" title="Remove attached image">✕</button>
                    <span style="font-size: 12px; color: #949ba4;">Image attached from clipboard</span>
                </div>

                <div id="input-box-wrapper" class="input-box">
                    <input id="message-input" type="text" placeholder="Message #general..." disabled />
                </div>
            </div>
        </div>

        <script>
            let ws;
            let myUsername = "";

            let activeTypers = new Set();
            let typingTimeout = null;
            let pastedImageDataUrl = null;

            let lastMsgSender = null;
            let lastMsgTimestamp = 0;

            let currentRoom = null;
            let localStream = null;
            let localScreenStream = null;
            let peerConnections = {};
            let iceQueues = {};
            let roomMembers = {};
            let knownPrivateRooms = new Set();
            let audioAnalyzers = {};
            let audioInterval = null;
            let pendingInviteRoom = null;
            let isMuted = false;
            let isDeafened = false;

            const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

            // --- Client-side decryption ---------------------------------------------
            // The server encrypts every chat message with AES-256-GCM using a key
            // derived (PBKDF2-SHA256, 100k iterations) from a fixed global passphrase
            // and salt. This mirrors that derivation with SubtleCrypto so the browser
            // can turn `ciphertext` + `iv` back into readable text.
            const GLOBAL_PASSPHRASE = "RUSTCORD_SERVER_GLOBAL_SECRET_KEY";
            const GLOBAL_SALT = "rust_cord_secure_salt_2026";

            const cryptoKeyPromise = deriveGlobalKey();

            async function deriveGlobalKey() {
                const enc = new TextEncoder();
                const baseKey = await crypto.subtle.importKey(
                    "raw",
                    enc.encode(GLOBAL_PASSPHRASE),
                    "PBKDF2",
                    false,
                    ["deriveKey"]
                );
                return crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: enc.encode(GLOBAL_SALT),
                        iterations: 100000,
                        hash: "SHA-256"
                    },
                    baseKey,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["decrypt"]
                );
            }

            function b64ToBytes(b64) {
                const bin = atob(b64);
                const bytes = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                return bytes;
            }

            async function decryptMessage(ciphertextB64, ivB64) {
                try {
                    const key = await cryptoKeyPromise;
                    const ciphertext = b64ToBytes(ciphertextB64);
                    const iv = b64ToBytes(ivB64);
                    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
                    return new TextDecoder().decode(plainBuf);
                } catch (e) {
                    console.error("Failed to decrypt message:", e);
                    return "[Unable to decrypt message]";
                }
            }
            // ---------------------------------------------------------------------------

            DOMPurify.setConfig({
                ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'code', 'pre', 'br', 'p', 'span', 'img', 'video', 'ul', 'ol', 'li'],
                ALLOWED_ATTR: ['href', 'src', 'controls', 'class', 'alt', 'loading', 'target', 'rel'],
                ALLOW_DATA_ATTR: false
            });

            window.addEventListener('DOMContentLoaded', () => {
                const savedUser = localStorage.getItem('rc_username');
                if (savedUser) document.getElementById('username-input').value = savedUser;

                const hash = window.location.hash;
                if (hash.startsWith('#room=')) {
                    pendingInviteRoom = hash.replace('#room=', '');
                }

                if (savedUser) {
                    attemptJoin();
                }

                document.getElementById('message-input').addEventListener('paste', handleClipboardPaste);
            });

            function handleClipboardPaste(e) {
                const items = (e.clipboardData || e.originalEvent.clipboardData).items;
                for (let item of items) {
                    if (item.type.indexOf('image') === 0) {
                        e.preventDefault();
                        const blob = item.getAsFile();
                        const reader = new FileReader();
                        reader.onload = function(event) {
                            pastedImageDataUrl = event.target.result;
                            showImagePreview(pastedImageDataUrl);
                        };
                        reader.readAsDataURL(blob);
                        break;
                    }
                }
            }

            function showImagePreview(dataUrl) {
                const container = document.getElementById('image-preview-container');
                const img = document.getElementById('image-preview');
                const boxWrapper = document.getElementById('input-box-wrapper');

                img.src = dataUrl;
                container.style.display = 'flex';
                boxWrapper.classList.add('has-preview');
            }

            function clearPastedImage() {
                pastedImageDataUrl = null;
                const container = document.getElementById('image-preview-container');
                const img = document.getElementById('image-preview');
                const boxWrapper = document.getElementById('input-box-wrapper');

                img.src = "";
                container.style.display = 'none';
                boxWrapper.classList.remove('has-preview');
            }

            async function attemptJoin() {
                const userVal = document.getElementById('username-input').value.trim();
                const errorDiv = document.getElementById('error-msg');
                errorDiv.style.display = 'none';

                if (!userVal) {
                    showError("Username is required!");
                    return;
                }

                myUsername = userVal;

                const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${protocol}//${location.host}/ws`);

                ws.onopen = () => {
                    ws.send(JSON.stringify({ type: "Join", username: myUsername }));
                };

                ws.onmessage = async (e) => {
                    const event = JSON.parse(e.data);

                    if (event.type === 'JoinSuccess') {
                        localStorage.setItem('rc_username', myUsername);

                        document.getElementById('modal').style.display = 'none';
                        const msgInput = document.getElementById('message-input');
                        msgInput.disabled = false;
                        msgInput.focus();

                        if (pendingInviteRoom) {
                            addPrivateRoom(pendingInviteRoom);
                            joinVoiceRoom(pendingInviteRoom);
                        }
                    }
                    else if (event.type === 'JoinError') {
                        showError(event.error);
                        ws.close();
                    }
                    else if (event.type === 'UserList') {
                        updateUserList(event.users);
                    }
                    else if (event.type === 'History') {
                        document.getElementById('messages').innerHTML = '';
                        lastMsgSender = null;
                        lastMsgTimestamp = 0;
                        for (let msg of event.messages) {
                            await renderMessage(msg);
                        }
                    }
                    else if (event.type === 'Message') {
                        await renderMessage(event);
                    }
                    else if (event.type === 'Typing') {
                        handleTypingEvent(event.username, event.is_typing);
                    }
                    else if (event.type === 'VoiceSignal') {
                        handleVoiceSignal(event.from, event.signal);
                    }
                    else if (event.type === 'VoiceInvite') {
                        if (event.target === myUsername) {
                            addPrivateRoom(event.room_id);
                            showInviteToast(event.from, event.room_id);
                        }
                    }
                    else if (event.type === 'VoiceStateUpdate') {
                        handleVoiceStateUpdate(event.username, event.room_id);
                    }
                    else if (event.type === 'DeleteVoiceRoom') {
                        handleDeleteVoiceRoom(event.room_id);
                    }
                };
            }

            function showError(msg) {
                const errorDiv = document.getElementById('error-msg');
                errorDiv.innerText = msg;
                errorDiv.style.display = 'block';
            }

            function send() {
                const input = document.getElementById('message-input');
                let rawText = input.value.trim();

                if (pastedImageDataUrl) {
                    rawText += (rawText ? "\n" : "") + `![Attached Image](${pastedImageDataUrl})`;
                }

                if (!rawText || !ws) return;

                notifyTyping(false);
                ws.send(JSON.stringify({
                    type: "Send",
                    text: rawText
                }));

                input.value = '';
                clearPastedImage();
            }

            async function renderMessage(msg) {
                const box = document.getElementById('messages');
                const rawPlaintext = await decryptMessage(msg.ciphertext, msg.iv);
                const sender = msg.username || 'Anonymous';
                const initial = sender.charAt(0).toUpperCase();

                let safeText = escapeHtml(rawPlaintext);
                let parsedHTML = marked.parse(safeText);

                parsedHTML = parsedHTML.replace(/(https?:\/\/[^\s<]+?\.(?:png|jpg|jpeg|gif|webp))/gi, '<img src="$1" loading="lazy" />');
                parsedHTML = parsedHTML.replace(/(https?:\/\/[^\s<]+?\.(?:mp4|webm|ogg))/gi, '<video controls src="$1"></video>');
                parsedHTML = parsedHTML.replace(/&lt;img src=&quot;(data:image\/[a-zA-Z]+;base64,[^&]+)&quot; alt=&quot;Attached Image&quot;&gt;/g, '<img src="$1" alt="Attached Image" />');

                const cleanBody = DOMPurify.sanitize(parsedHTML);

                const msgDate = new Date(msg.timestamp * 1000);
                const timeStr = msgDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                const isGrouped = (sender === lastMsgSender) && ((msg.timestamp - lastMsgTimestamp) < 300);

                lastMsgSender = sender;
                lastMsgTimestamp = msg.timestamp;

                if (isGrouped) {
                    box.innerHTML += `
                        <div class="msg-group grouped">
                            <div class="avatar-col"><span class="hover-time">${timeStr}</span></div>
                            <div class="msg-content"><div class="body">${cleanBody}</div></div>
                        </div>`;
                } else {
                    box.innerHTML += `
                        <div class="msg-group">
                            <div class="avatar-col"><div class="avatar">${initial}</div></div>
                            <div class="msg-content">
                                <div class="msg-header">
                                    <span class="username">${escapeHtml(sender)}</span>
                                    <span class="timestamp">${timeStr}</span>
                                </div>
                                <div class="body">${cleanBody}</div>
                            </div>
                        </div>`;
                }

                box.scrollTop = box.scrollHeight;
            }

            function updateUserList(users) {
                const list = document.getElementById('user-list');
                document.getElementById('user-count').innerText = users.length;
                list.innerHTML = '';
                users.forEach(u => {
                    const isSelf = u === myUsername;
                    const inviteBtn = isSelf ? '' : `<button class="invite-btn" onclick="inviteUser('${escapeHtml(u)}')">Invite</button>`;
                    list.innerHTML += `
                        <li>
                            <div class="user-info">
                                <span class="status-dot"></span>
                                <span>${escapeHtml(u)}</span>
                            </div>
                            ${inviteBtn}
                        </li>
                    `;
                });
            }

            function addPrivateRoom(roomId) {
                if (knownPrivateRooms.has(roomId)) return;
                knownPrivateRooms.add(roomId);

                const container = document.getElementById('private-rooms-list');
                const shortName = roomId.length > 12 ? roomId.substring(0, 10) + '...' : roomId;

                const wrapper = document.createElement('div');
                wrapper.id = `vc-wrapper-${roomId}`;
                wrapper.innerHTML = `
                    <div id="vc-item-${roomId}" class="vc-item" onclick="toggleVoiceChannel('${roomId}')">
                        <span>🔒 Private: ${shortName}</span>
                        <span class="vc-delete-btn" title="Delete VC" onclick="event.stopPropagation(); deletePrivateVC('${roomId}')">🗑️</span>
                    </div>
                    <ul id="roster-${roomId}" class="vc-roster"></ul>
                `;
                container.appendChild(wrapper);
            }

            function deletePrivateVC(roomId) {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "DeleteVoiceRoom", room_id: roomId }));
                }
            }

            function handleDeleteVoiceRoom(roomId) {
                if (currentRoom === roomId) {
                    leaveVoiceChannel();
                }
                knownPrivateRooms.delete(roomId);
                const elem = document.getElementById(`vc-wrapper-${roomId}`);
                if (elem) elem.remove();

                // Clean up any stale roster entries pointing at the deleted room
                Object.keys(roomMembers).forEach(user => {
                    if (roomMembers[user] === roomId) delete roomMembers[user];
                });
                renderVCRosters();
            }

            async function toggleVoiceChannel(roomName) {
                if (currentRoom === roomName) {
                    leaveVoiceChannel();
                    return;
                }
                if (currentRoom) leaveVoiceChannel();
                await joinVoiceRoom(roomName);
            }

            async function joinVoiceRoom(roomName) {
                currentRoom = roomName;

                document.getElementById('vc-general').classList.toggle('active', roomName === 'general');
                knownPrivateRooms.forEach(id => {
                    const item = document.getElementById(`vc-item-${id}`);
                    if (item) item.classList.toggle('active', id === roomName);
                });

                document.getElementById('btn-screen').disabled = false;

                try {
                    localStream = await navigator.mediaDevices.getUserMedia({
                        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
                        video: false
                    });
                    setupAudioAnalyzer(myUsername, localStream);
                } catch (err) {
                    alert("Could not access microphone: " + err.message);
                    return;
                }

                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "VoiceStateUpdate", room_id: currentRoom }));
                }

                Object.keys(roomMembers).forEach(targetUser => {
                    if (targetUser !== myUsername && roomMembers[targetUser] === currentRoom) {
                        createPeerConnection(targetUser);
                    }
                });

                startSpeakingMonitor();
            }

            function leaveVoiceChannel() {
                if (!currentRoom) return;

                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "VoiceStateUpdate", room_id: null }));
                }

                currentRoom = null;
                document.getElementById('vc-general').classList.remove('active');
                knownPrivateRooms.forEach(id => {
                    const item = document.getElementById(`vc-item-${id}`);
                    if (item) item.classList.remove('active');
                });

                const screenBtn = document.getElementById('btn-screen');
                screenBtn.disabled = true;
                screenBtn.classList.remove('active');

                if (localStream) {
                    localStream.getTracks().forEach(t => t.stop());
                    localStream = null;
                }
                if (localScreenStream) {
                    localScreenStream.getTracks().forEach(t => t.stop());
                    localScreenStream = null;
                    document.getElementById('video-grid').style.display = 'none';
                }

                Object.keys(peerConnections).forEach(target => {
                    peerConnections[target].close();
                    delete peerConnections[target];
                });

                iceQueues = {};
                document.getElementById('remote-audio-container').innerHTML = '';
                document.getElementById('video-grid').innerHTML = '';
                document.getElementById('video-grid').style.display = 'none';

                stopSpeakingMonitor();
                renderVCRosters();
            }

            function handleVoiceStateUpdate(username, roomId) {
                if (roomId) {
                    roomMembers[username] = roomId;
                    if (roomId !== 'general') addPrivateRoom(roomId);
                } else {
                    delete roomMembers[username];
                }

                if (currentRoom && roomId === currentRoom && username !== myUsername) {
                    createPeerConnection(username);
                }

                renderVCRosters();
            }

            function renderVCRosters() {
                const genRoster = document.getElementById('roster-general');
                genRoster.innerHTML = '';

                knownPrivateRooms.forEach(rId => {
                    const roster = document.getElementById(`roster-${rId}`);
                    if (roster) roster.innerHTML = '';
                });

                Object.keys(roomMembers).forEach(user => {
                    const room = roomMembers[user];
                    const initial = user.charAt(0).toUpperCase();
                    const li = document.createElement('li');
                    li.className = 'vc-user';
                    li.id = `vc-user-${user}`;
                    li.innerHTML = `
                        <div class="vc-user-avatar" id="avatar-${user}">${initial}</div>
                        <span>${escapeHtml(user)}</span>
                    `;

                    if (room === 'general') {
                        genRoster.appendChild(li);
                    } else {
                        const targetRoster = document.getElementById(`roster-${room}`);
                        if (targetRoster) targetRoster.appendChild(li);
                    }
                });
            }

            function setupAudioAnalyzer(user, stream) {
                try {
                    const ctx = new (window.AudioContext || window.webkitAudioContext)();
                    if (ctx.state === 'suspended') {
                        ctx.resume();
                    }
                    const src = ctx.createMediaStreamSource(stream);
                    const analyzer = ctx.createAnalyser();
                    analyzer.fftSize = 256;
                    src.connect(analyzer);
                    audioAnalyzers[user] = { analyzer, context: ctx };
                } catch (e) { console.error("Audio Analysis error", e); }
            }

            function startSpeakingMonitor() {
                if (audioInterval) clearInterval(audioInterval);
                audioInterval = setInterval(() => {
                    Object.keys(audioAnalyzers).forEach(user => {
                        const { analyzer } = audioAnalyzers[user];
                        const data = new Uint8Array(analyzer.frequencyBinCount);
                        analyzer.getByteFrequencyData(data);

                        let sum = 0;
                        for (let i = 0; i < data.length; i++) sum += data[i];
                        const avg = sum / data.length;

                        const avatar = document.getElementById(`avatar-${user}`);
                        if (avatar) {
                            if (avg > 12) avatar.classList.add('speaking');
                            else avatar.classList.remove('speaking');
                        }
                    });
                }, 100);
            }

            function stopSpeakingMonitor() {
                if (audioInterval) clearInterval(audioInterval);
                audioAnalyzers = {};
            }

            // --- WebRTC peer connections (perfect negotiation) ------------------------
            // Two peers can both try to join around the same time. The old code always
            // made *both* sides "initiators" of their connection to each other, so both
            // called createOffer() simultaneously — an offer/offer collision that made
            // setRemoteDescription throw and silently kill audio for everyone whenever a
            // 2nd+ person was in a room. This uses the standard "perfect negotiation"
            // pattern: politeness is decided deterministically per pair (by username
            // comparison) and negotiation is *always* listened for on both sides, so
            // adding a track later (e.g. screen share) also renegotiates correctly,
            // regardless of who started the connection.
            function isPolite(targetUser) {
                return myUsername > targetUser;
            }

            function createPeerConnection(targetUser) {
                if (peerConnections[targetUser]) return peerConnections[targetUser];

                const pc = new RTCPeerConnection(rtcConfig);
                pc.makingOffer = false;
                pc.polite = isPolite(targetUser);
                peerConnections[targetUser] = pc;
                iceQueues[targetUser] = [];

                if (localStream) {
                    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
                }
                if (localScreenStream) {
                    localScreenStream.getTracks().forEach(track => pc.addTrack(track, localScreenStream));
                }

                pc.ontrack = (evt) => {
                    if (evt.track.kind === 'audio') {
                        let audioEl = document.getElementById(`audio-${targetUser}`);
                        if (!audioEl) {
                            audioEl = document.createElement('audio');
                            audioEl.id = `audio-${targetUser}`;
                            audioEl.autoplay = true;
                            document.getElementById('remote-audio-container').appendChild(audioEl);
                        }
                        audioEl.srcObject = evt.streams[0];
                        audioEl.muted = isDeafened;
                        audioEl.play().catch(e => console.log("Autoplay prevention:", e));
                        setupAudioAnalyzer(targetUser, evt.streams[0]);
                    } else if (evt.track.kind === 'video') {
                        let grid = document.getElementById('video-grid');
                        grid.style.display = 'flex';
                        let videoEl = document.getElementById(`video-${targetUser}`);
                        if (!videoEl) {
                            videoEl = document.createElement('video');
                            videoEl.id = `video-${targetUser}`;
                            videoEl.autoplay = true;
                            videoEl.playsInline = true;
                            grid.appendChild(videoEl);
                        }
                        videoEl.srcObject = evt.streams[0];
                    }
                };

                pc.onicecandidate = (evt) => {
                    if (evt.candidate) {
                        sendVoiceSignal(targetUser, { candidate: evt.candidate });
                    }
                };

                // Attached unconditionally on every connection (not just an "initiator"
                // flag) so renegotiation — e.g. starting a screen share after the call is
                // already up — works no matter which side adds the new track.
                pc.onnegotiationneeded = async () => {
                    try {
                        pc.makingOffer = true;
                        await pc.setLocalDescription();
                        sendVoiceSignal(targetUser, { sdp: pc.localDescription });
                    } catch (err) {
                        console.error("Negotiation error:", err);
                    } finally {
                        pc.makingOffer = false;
                    }
                };

                return pc;
            }

            async function handleVoiceSignal(fromUser, signal) {
                let pc = peerConnections[fromUser] || createPeerConnection(fromUser);

                if (signal.sdp) {
                    const description = signal.sdp;
                    const offerCollision = description.type === 'offer' &&
                        (pc.makingOffer || pc.signalingState !== 'stable');

                    const ignoreOffer = !pc.polite && offerCollision;
                    if (ignoreOffer) return;

                    try {
                        if (offerCollision) {
                            // Polite side: roll back our own offer and accept theirs instead.
                            await Promise.all([
                                pc.setLocalDescription({ type: 'rollback' }),
                                pc.setRemoteDescription(new RTCSessionDescription(description))
                            ]);
                        } else {
                            await pc.setRemoteDescription(new RTCSessionDescription(description));
                        }
                    } catch (err) {
                        console.error("setRemoteDescription failed:", err);
                        return;
                    }

                    if (iceQueues[fromUser]) {
                        while (iceQueues[fromUser].length > 0) {
                            const cand = iceQueues[fromUser].shift();
                            try { await pc.addIceCandidate(cand); } catch (e) { console.error(e); }
                        }
                    }

                    if (description.type === 'offer') {
                        await pc.setLocalDescription();
                        sendVoiceSignal(fromUser, { sdp: pc.localDescription });
                    }
                } else if (signal.candidate) {
                    const candidate = new RTCIceCandidate(signal.candidate);
                    if (pc.remoteDescription && pc.remoteDescription.type) {
                        try { await pc.addIceCandidate(candidate); } catch (e) { console.error(e); }
                    } else {
                        if (!iceQueues[fromUser]) iceQueues[fromUser] = [];
                        iceQueues[fromUser].push(candidate);
                    }
                }
            }
            // ---------------------------------------------------------------------------

            function sendVoiceSignal(target, signal) {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "VoiceSignal", target, signal }));
                }
            }

            function toggleMute() {
                isMuted = !isMuted;
                if (localStream) {
                    localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
                }
                const btn = document.getElementById('btn-mute');
                btn.classList.toggle('active', isMuted);
                btn.innerText = isMuted ? "🎙️ Unmute" : "🎙️ Mute";
            }

            function toggleDeafen() {
                isDeafened = !isDeafened;
                const audios = document.querySelectorAll('#remote-audio-container audio');
                audios.forEach(a => a.muted = isDeafened);
                const btn = document.getElementById('btn-deaf');
                btn.classList.toggle('active', isDeafened);
                btn.innerText = isDeafened ? "🎧 Undeafen" : "🎧 Deafen";
            }

            async function toggleScreenShare() {
                if (!currentRoom) {
                    alert("Please join a voice room first!");
                    return;
                }

                if (localScreenStream) {
                    localScreenStream.getTracks().forEach(t => t.stop());
                    localScreenStream = null;
                    document.getElementById('btn-screen').classList.remove('active');
                    const localVid = document.getElementById('video-local');
                    if (localVid) localVid.remove();
                    if (document.querySelectorAll('#video-grid video').length === 0) {
                        document.getElementById('video-grid').style.display = 'none';
                    }
                    return;
                }

                try {
                    localScreenStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
                    document.getElementById('btn-screen').classList.add('active');
                    const grid = document.getElementById('video-grid');
                    grid.style.display = 'flex';

                    let localVid = document.getElementById('video-local');
                    if (!localVid) {
                        localVid = document.createElement('video');
                        localVid.id = 'video-local';
                        localVid.autoplay = true;
                        localVid.muted = true;
                        grid.appendChild(localVid);
                    }
                    localVid.srcObject = localScreenStream;

                    // addTrack fires onnegotiationneeded on this pc (now attached on every
                    // connection), so the remote side gets a proper renegotiated offer.
                    Object.values(peerConnections).forEach(pc => {
                        localScreenStream.getTracks().forEach(track => pc.addTrack(track, localScreenStream));
                    });

                } catch (err) {
                    console.error("Screen share error: ", err);
                }
            }

            function inviteUser(targetUser) {
                const roomToken = "priv-" + Math.random().toString(36).substring(2, 7);
                addPrivateRoom(roomToken);

                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "VoiceInvite", target: targetUser, room_id: roomToken }));
                }

                toggleVoiceChannel(roomToken);
            }

            function showInviteToast(fromUser, roomId) {
                pendingInviteRoom = roomId;
                document.getElementById('toast-title').innerText = `Voice Call from ${fromUser}`;
                document.getElementById('toast-body').innerText = `${fromUser} invited you to a private voice room.`;
                document.getElementById('toast').style.display = 'block';
            }

            function acceptInvite() {
                document.getElementById('toast').style.display = 'none';
                if (pendingInviteRoom) {
                    addPrivateRoom(pendingInviteRoom);
                    toggleVoiceChannel(pendingInviteRoom);
                    pendingInviteRoom = null;
                }
            }

            function declineInvite() {
                document.getElementById('toast').style.display = 'none';
                pendingInviteRoom = null;
            }

            function handleTypingEvent(user, isTyping) {
                if (user === myUsername) return;
                if (isTyping) activeTypers.add(user);
                else activeTypers.delete(user);

                const indicator = document.getElementById('typing-indicator');
                const typers = Array.from(activeTypers);
                if (typers.length === 0) indicator.innerText = '';
                else if (typers.length === 1) indicator.innerText = `${typers[0]} is typing...`;
                else indicator.innerText = `Several people are typing...`;
            }

            function notifyTyping(isTyping) {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "Typing", is_typing: isTyping }));
                }
            }

            const inputElem = document.getElementById('message-input');
            inputElem.addEventListener('input', () => {
                notifyTyping(true);
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(() => notifyTyping(false), 2000);
            });

            inputElem.addEventListener('keypress', (e) => { if (e.key === 'Enter') send(); });
            document.getElementById('username-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') attemptJoin(); });

            function escapeHtml(text) {
                return text
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }
        </script>
    </body>
    </html>
    "#)
}

async fn ws_handler(ws: WebSocketUpgrade, state: Arc<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let conn_id = OsRng.next_u64() as usize;
    let mut current_username: Option<String> = None;

    let mut rx = state.tx.subscribe();

    let state_tx_task = state.clone();
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg_str) = rx.recv().await {
            if sender.send(Message::Text(msg_str)).await.is_err() {
                break;
            }
        }
    });

    let state_recv_task = state.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                if let Ok(client_event) = serde_json::from_str::<ClientEvent>(&text) {
                    match client_event {
                        ClientEvent::Join { username } => {
                            let mut users = state_recv_task.users.lock().unwrap();
                            let clean_name = username.trim().to_string();

                            if clean_name.is_empty() {
                                let err_event = ServerEvent::JoinError { error: "Username cannot be empty!".to_string() };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&err_event).unwrap());
                                continue;
                            }

                            if users.values().any(|u| u.eq_ignore_ascii_case(&clean_name)) {
                                let err_event = ServerEvent::JoinError { error: "Username is already taken!".to_string() };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&err_event).unwrap());
                                continue;
                            }

                            users.insert(conn_id, clean_name.clone());
                            current_username = Some(clean_name.clone());

                            let success_event = ServerEvent::JoinSuccess { username: clean_name.clone() };
                            let _ = state_recv_task.tx.send(serde_json::to_string(&success_event).unwrap());

                            let active_users: Vec<String> = users.values().cloned().collect();
                            let user_list_event = ServerEvent::UserList { users: active_users };
                            let _ = state_recv_task.tx.send(serde_json::to_string(&user_list_event).unwrap());

                            let msgs = state_recv_task.messages.lock().unwrap();
                            let history: Vec<EncryptedMessage> = msgs.iter().cloned().collect();
                            drop(msgs);

                            let history_event = ServerEvent::History { messages: history };
                            let _ = state_recv_task.tx.send(serde_json::to_string(&history_event).unwrap());

                            let voice_states = state_recv_task.voice_states.lock().unwrap();
                            for (u, r) in voice_states.iter() {
                                let vs_event = ServerEvent::VoiceStateUpdate {
                                    username: u.clone(),
                                    room_id: Some(r.clone()),
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&vs_event).unwrap());
                            }
                        }
                        ClientEvent::Send { text } => {
                            if let Some(ref name) = current_username {
                                let mut nonce_bytes = [0u8; 12];
                                OsRng.fill_bytes(&mut nonce_bytes);
                                let nonce = Nonce::from_slice(&nonce_bytes);

                                if let Ok(ciphertext_bytes) = state_recv_task.cipher.encrypt(nonce, text.as_bytes()) {
                                    let ciphertext_b64 = BASE64_STANDARD.encode(ciphertext_bytes);
                                    let iv_b64 = BASE64_STANDARD.encode(nonce_bytes);

                                    let timestamp = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();

                                    let enc_msg = EncryptedMessage {
                                        username: name.clone(),
                                        ciphertext: ciphertext_b64.clone(),
                                        iv: iv_b64.clone(),
                                        timestamp,
                                    };

                                    let mut msgs = state_recv_task.messages.lock().unwrap();
                                    msgs.push_back(enc_msg);
                                    if msgs.len() > 100 {
                                        msgs.pop_front();
                                    }
                                    drop(msgs);

                                    let msg_event = ServerEvent::Message {
                                        username: name.clone(),
                                        ciphertext: ciphertext_b64,
                                        iv: iv_b64,
                                        timestamp,
                                    };
                                    let _ = state_recv_task.tx.send(serde_json::to_string(&msg_event).unwrap());
                                }
                            }
                        }
                        ClientEvent::Typing { is_typing } => {
                            if let Some(ref name) = current_username {
                                let typing_event = ServerEvent::Typing {
                                    username: name.clone(),
                                    is_typing,
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&typing_event).unwrap());
                            }
                        }
                        ClientEvent::VoiceSignal { target, signal } => {
                            if let Some(ref name) = current_username {
                                let vs_event = ServerEvent::VoiceSignal {
                                    from: name.clone(),
                                    target,
                                    signal,
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&vs_event).unwrap());
                            }
                        }
                        ClientEvent::VoiceInvite { target, room_id } => {
                            if let Some(ref name) = current_username {
                                let vi_event = ServerEvent::VoiceInvite {
                                    from: name.clone(),
                                    target,
                                    room_id,
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&vi_event).unwrap());
                            }
                        }
                        ClientEvent::VoiceStateUpdate { room_id } => {
                            if let Some(ref name) = current_username {
                                let mut voice_states = state_recv_task.voice_states.lock().unwrap();
                                if let Some(ref r) = room_id {
                                    voice_states.insert(name.clone(), r.clone());
                                } else {
                                    voice_states.remove(name);
                                }
                                drop(voice_states);

                                let vs_event = ServerEvent::VoiceStateUpdate {
                                    username: name.clone(),
                                    room_id,
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&vs_event).unwrap());
                            }
                        }
                        ClientEvent::DeleteVoiceRoom { room_id } => {
                            // Fix: previously this only dropped the room's members from
                            // server-side voice_states without telling *their* clients
                            // they'd been removed, leaving those clients still holding
                            // mic/peer state for a room that no longer exists anywhere
                            // else. Now every evicted user gets an explicit
                            // VoiceStateUpdate{room_id: None} so their own client tears
                            // down its local state too.
                            let mut voice_states = state_recv_task.voice_states.lock().unwrap();
                            let removed_users: Vec<String> = voice_states
                                .iter()
                                .filter(|(_, r)| **r == room_id)
                                .map(|(u, _)| u.clone())
                                .collect();
                            voice_states.retain(|_, r| r != &room_id);
                            drop(voice_states);

                            for u in removed_users {
                                let vs_event = ServerEvent::VoiceStateUpdate {
                                    username: u,
                                    room_id: None,
                                };
                                let _ = state_recv_task.tx.send(serde_json::to_string(&vs_event).unwrap());
                            }

                            let del_event = ServerEvent::DeleteVoiceRoom { room_id };
                            let _ = state_recv_task.tx.send(serde_json::to_string(&del_event).unwrap());
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    let mut users = state.users.lock().unwrap();
    if let Some(username) = users.remove(&conn_id) {
        let active_users: Vec<String> = users.values().cloned().collect();
        drop(users);

        let user_list_event = ServerEvent::UserList { users: active_users };
        let _ = state.tx.send(serde_json::to_string(&user_list_event).unwrap());

        let mut voice_states = state.voice_states.lock().unwrap();
        if voice_states.remove(&username).is_some() {
            drop(voice_states);
            let vs_event = ServerEvent::VoiceStateUpdate {
                username,
                room_id: None,
            };
            let _ = state.tx.send(serde_json::to_string(&vs_event).unwrap());
        }
    }
}
