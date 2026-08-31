use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce, Key
};
use base64::{Engine as _, ENGINE_STANDARD};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

// Server-wide Global Secret Key derivation configuration
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
            let iceQueues = {}; // Queue ICE candidates if RemoteDescription is not set yet
            let roomMembers = {};
            let knownPrivateRooms = new Set();
            let audioAnalyzers = {};
            let audioInterval = null;
            let pendingInviteRoom = null;
            let isMuted = false;
            let isDeafened = false;
        
            const rtcConfig = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
        
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
                            renderMessage(msg);
                        }
                    } 
                    else if (event.type === 'Message') {
                        renderMessage(event);
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
        
            function renderMessage(msg) {
                const box = document.getElementById('messages');
                const rawPlaintext = msg.ciphertext;
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
        
                // Obtain local microphone before connecting to peers
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
        
                // Initialize connections to anyone already in this room
                Object.keys(roomMembers).forEach(targetUser => {
                    if (targetUser !== myUsername && roomMembers[targetUser] === currentRoom) {
                        createPeerConnection(targetUser, true);
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
                    createPeerConnection(username, true);
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
        
            function createPeerConnection(targetUser, isInitiator) {
                if (peerConnections[targetUser]) return peerConnections[targetUser];
        
                const pc = new RTCPeerConnection(rtcConfig);
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
        
                if (isInitiator) {
                    pc.onnegotiationneeded = async () => {
                        try {
                            const offer = await pc.createOffer();
                            await pc.setLocalDescription(offer);
                            sendVoiceSignal(targetUser, { sdp: pc.localDescription });
                        } catch (err) { console.error(err); }
                    };
                }
        
                return pc;
            }
        
            async function handleVoiceSignal(fromUser, signal) {
                let pc = peerConnections[fromUser] || createPeerConnection(fromUser, false);
        
                if (signal.sdp) {
                    await pc.setRemoteDescription(new RTCSessionDescription(signal.sdp));
                    
                    // Process queued candidates that arrived before SDP
                    if (iceQueues[fromUser]) {
                        while (iceQueues[fromUser].length > 0) {
                            const cand = iceQueues[fromUser].shift();
                            await pc.addIceCandidate(cand);
                        }
                    }
        
                    if (signal.sdp.type === 'offer') {
                        const answer = await pc.createAnswer();
                        await pc.setLocalDescription(answer);
                        sendVoiceSignal(fromUser, { sdp: pc.localDescription });
                    }
                } else if (signal.candidate) {
                    const candidate = new RTCIceCandidate(signal.candidate);
                    if (pc.remoteDescription && pc.remoteDescription.type) {
                        await pc.addIceCandidate(candidate);
                    } else {
                        if (!iceQueues[fromUser]) iceQueues[fromUser] = [];
                        iceQueues[fromUser].push(candidate);
                    }
                }
            }
        
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
    let mut rx = state.tx.subscribe();

    static NEXT_USER_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let my_id = NEXT_USER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut my_username = String::new();

    while let Some(Ok(Message::Text(text))) = receiver.next().await {
        if let Ok(ClientEvent::Join { username }) = serde_json::from_str(&text) {
            let username_trimmed = username.trim().to_string();
            
            let is_taken = {
                let users = state.users.lock().unwrap();
                users.values().any(|u| u.eq_ignore_ascii_case(&username_trimmed))
            };

            if is_taken {
                let err_evt = ServerEvent::JoinError { error: "Username is already taken! Please choose another.".into() };
                let _ = sender.send(Message::Text(serde_json::to_string(&err_evt).unwrap())).await;
                return;
            } else {
                {
                    let mut users = state.users.lock().unwrap();
                    users.insert(my_id, username_trimmed.clone());
                }
                
                my_username = username_trimmed;

                let success_evt = ServerEvent::JoinSuccess { username: my_username.clone() };
                let _ = sender.send(Message::Text(serde_json::to_string(&success_evt).unwrap())).await;
                
                let users_snapshot = state.users.lock().unwrap().clone();
                broadcast_user_list(&state, &users_snapshot);
                break;
            }
        }
    }

    if my_username.is_empty() { return; }

    // Decrypt history stored in memory on the fly for the joining client
    let history = {
        let msgs = state.messages.lock().unwrap();
        msgs.iter().map(|msg| {
            let mut decrypted = msg.clone();
            if let (Ok(iv_bytes), Ok(ct_bytes)) = (
                ENGINE_STANDARD.decode(&msg.iv),
                ENGINE_STANDARD.decode(&msg.ciphertext),
            ) {
                let nonce = Nonce::from_slice(&iv_bytes);
                if let Ok(plaintext) = state.cipher.decrypt(nonce, ct_bytes.as_ref()) {
                    decrypted.ciphertext = String::from_utf8_lossy(&plaintext).to_string();
                }
            }
            decrypted
        }).collect::<Vec<_>>()
    };
    
    let history_event = ServerEvent::History { messages: history };
    let _ = sender.send(Message::Text(serde_json::to_string(&history_event).unwrap())).await;

    let existing_voice_states = {
        let v_states = state.voice_states.lock().unwrap();
        v_states.iter().map(|(u, r)| (u.clone(), r.clone())).collect::<Vec<_>>()
    };

    for (u, r) in existing_voice_states {
        let evt = ServerEvent::VoiceStateUpdate { username: u, room_id: Some(r) };
        let _ = sender.send(Message::Text(serde_json::to_string(&evt).unwrap())).await;
    }

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let state_clone = state.clone();
    let username_clone = my_username.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            if let Ok(event) = serde_json::from_str::<ClientEvent>(&text) {
                match event {
                    ClientEvent::Send { text } => {
                        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        
                        // Encrypt plaintext message with Global AES-256-GCM Key
                        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                        if let Ok(ciphertext_bytes) = state_clone.cipher.encrypt(&nonce, text.as_bytes()) {
                            let ciphertext_b64 = ENGINE_STANDARD.encode(ciphertext_bytes);
                            let iv_b64 = ENGINE_STANDARD.encode(nonce);

                            let encrypted_msg = EncryptedMessage {
                                username: username_clone.clone(),
                                ciphertext: ciphertext_b64.clone(),
                                iv: iv_b64.clone(),
                                timestamp,
                            };

                            {
                                let mut msgs = state_clone.messages.lock().unwrap();
                                msgs.push_back(encrypted_msg);
                            }

                            // Broadcast plaintext to connected authenticated sockets, ciphertext to capture tools
                            let evt = ServerEvent::Message {
                                username: username_clone.clone(),
                                ciphertext: text,
                                iv: iv_b64,
                                timestamp,
                            };
                            let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                        }
                    }
                    ClientEvent::Typing { is_typing } => {
                        let evt = ServerEvent::Typing { username: username_clone.clone(), is_typing };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::VoiceSignal { target, signal } => {
                        let evt = ServerEvent::VoiceSignal { from: username_clone.clone(), target, signal };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::VoiceInvite { target, room_id } => {
                        let evt = ServerEvent::VoiceInvite { from: username_clone.clone(), target, room_id };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::VoiceStateUpdate { room_id } => {
                        {
                            let mut v_states = state_clone.voice_states.lock().unwrap();
                            if let Some(ref r) = room_id {
                                v_states.insert(username_clone.clone(), r.clone());
                            } else {
                                v_states.remove(&username_clone);
                            }
                        }
                        let evt = ServerEvent::VoiceStateUpdate { username: username_clone.clone(), room_id };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::DeleteVoiceRoom { room_id } => {
                        let evt = ServerEvent::DeleteVoiceRoom { room_id };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::Join { .. } => {}
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    {
        let mut users = state.users.lock().unwrap();
        users.remove(&my_id);
        let users_snapshot = users.clone();
        broadcast_user_list(&state, &users_snapshot);

        let mut v_states = state.voice_states.lock().unwrap();
        v_states.remove(&my_username);
        let evt = ServerEvent::VoiceStateUpdate { username: my_username.clone(), room_id: None };
        let _ = state.tx.send(serde_json::to_string(&evt).unwrap());
    }
}

fn broadcast_user_list(state: &AppState, users: &HashMap<usize, String>) {
    let user_names: Vec<String> = users.values().cloned().collect();
    let event = ServerEvent::UserList { users: user_names };
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = state.tx.send(json);
    }
}
