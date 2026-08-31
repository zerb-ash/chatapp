use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

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
    Message(EncryptedMessage),
    UserList { users: Vec<String> },
    Typing { username: String, is_typing: bool },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientEvent {
    Join { username: String },
    Send { ciphertext: String, iv: String },
    Typing { is_typing: bool },
}

struct AppState {
    tx: broadcast::Sender<String>,
    users: Mutex<HashMap<usize, String>>,
    messages: Mutex<VecDeque<EncryptedMessage>>,
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel::<String>(100);
    let state = Arc::new(AppState {
        tx,
        users: Mutex::new(HashMap::new()),
        messages: Mutex::new(VecDeque::new()),
    });

    // Background purge thread: Removes messages older than 24 hours (86,400s)
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
            
            #sidebar { width: 240px; background: #2b2d31; display: flex; flex-direction: column; border-right: 1px solid #1f2023; }
            .sidebar-header { padding: 16px; font-weight: bold; color: #f2f5f7; border-bottom: 1px solid #1f2023; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
            #user-list { list-style: none; padding: 10px; overflow-y: auto; flex: 1; }
            #user-list li { display: flex; align-items: center; gap: 8px; padding: 8px; border-radius: 4px; font-size: 14px; color: #949ba4; }
            .status-dot { width: 8px; height: 8px; background: #23a55a; border-radius: 50%; display: inline-block; }

            #main { flex: 1; display: flex; flex-direction: column; background: #313338; }
            .chat-header { padding: 16px; background: #313338; border-bottom: 1px solid #1f2023; font-weight: bold; color: #f2f5f7; }
            #messages { flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 16px; }

            .msg-card { display: flex; gap: 14px; }
            .avatar { width: 40px; height: 40px; border-radius: 50%; background: #5865f2; color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; flex-shrink: 0; }
            .msg-content { display: flex; flex-direction: column; flex: 1; }
            .msg-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
            .username { font-weight: 600; color: #f2f5f7; font-size: 15px; }
            .timestamp { font-size: 11px; color: #949ba4; }
            .body { color: #dbdee1; font-size: 14px; line-height: 1.4; word-break: break-word; }

            .body img, .body video { max-width: 400px; max-height: 300px; border-radius: 8px; margin-top: 8px; display: block; }
            .body a { color: #00a8fc; text-decoration: none; }
            .body code { background: #2b2d31; padding: 2px 4px; border-radius: 4px; font-family: monospace; }

            .input-container { padding: 0 20px 20px 20px; position: relative; }
            .input-box { background: #383a40; border-radius: 8px; display: flex; align-items: center; padding: 0 16px; }
            #message-input { width: 100%; background: transparent; border: none; padding: 14px 0; color: #dbdee1; font-size: 14px; outline: none; }
            #typing-indicator { position: absolute; top: -20px; left: 24px; font-size: 12px; color: #b5bac1; font-style: italic; min-height: 16px; }

            #modal { position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 100; }
            .modal-box { background: #313338; padding: 32px; border-radius: 8px; width: 360px; text-align: center; }
            .modal-box h3 { color: #f2f5f7; margin-bottom: 8px; }
            .modal-box p { color: #949ba4; font-size: 13px; margin-bottom: 16px; }
            .modal-box input { width: 100%; padding: 10px; background: #1e1f22; border: 1px solid #111214; border-radius: 4px; color: white; margin-bottom: 12px; outline: none; }
            .modal-box button { width: 100%; padding: 12px; background: #5865f2; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
            #error-msg { color: #f23f43; font-size: 13px; margin-bottom: 10px; display: none; }
        </style>
    </head>
    <body>

        <div id="modal">
            <div class="modal-box">
                <h3>Welcome to RustCord</h3>
                <p>Enter a unique username and key to enter.</p>
                <div id="error-msg"></div>
                <input id="username-input" type="text" placeholder="Username" autofocus />
                <input id="room-key" type="password" placeholder="Passphrase (Secret Key)" />
                <button onclick="attemptJoin()">Join Server</button>
            </div>
        </div>

        <div id="sidebar">
            <div class="sidebar-header">Online Users — <span id="user-count">0</span></div>
            <ul id="user-list"></ul>
        </div>

        <div id="main">
            <div class="chat-header"># general</div>
            <div id="messages"></div>
            <div class="input-container">
                <div id="typing-indicator"></div>
                <div class="input-box">
                    <input id="message-input" type="text" placeholder="Message #general..." disabled />
                </div>
            </div>
        </div>

        <script>
            let ws;
            let myUsername = "";
            let cryptoKey = null;
            let activeTypers = new Set();
            let typingTimeout = null;

            // Auto-fill from localStorage on page load
            window.addEventListener('DOMContentLoaded', () => {
                const savedUser = localStorage.getItem('rc_username');
                const savedKey = localStorage.getItem('rc_key');
                if (savedUser) document.getElementById('username-input').value = savedUser;
                if (savedKey) document.getElementById('room-key').value = savedKey;

                if (savedUser && savedKey) {
                    attemptJoin();
                }
            });

            async function attemptJoin() {
                const userVal = document.getElementById('username-input').value.trim();
                const passVal = document.getElementById('room-key').value.trim();
                const errorDiv = document.getElementById('error-msg');
                errorDiv.style.display = 'none';

                if (!userVal || !passVal) {
                    showError("Username and Passphrase are required!");
                    return;
                }

                // Derive AES-GCM Key from passphrase
                const enc = new TextEncoder();
                const keyMaterial = await crypto.subtle.importKey(
                    "raw", enc.encode(passVal), "PBKDF2", false, ["deriveKey"]
                );
                cryptoKey = await crypto.subtle.deriveKey(
                    { name: "PBKDF2", salt: enc.encode("rust_salt_2026"), iterations: 100000, hash: "SHA-256" },
                    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
                );

                myUsername = userVal;

                // Establish WebSocket Connection
                const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${protocol}//${location.host}/ws`);

                ws.onopen = () => {
                    ws.send(JSON.stringify({ type: "Join", username: myUsername }));
                };

                ws.onmessage = async (e) => {
                    const event = JSON.parse(e.data);

                    if (event.type === 'JoinSuccess') {
                        // Store credentials in localStorage
                        localStorage.setItem('rc_username', myUsername);
                        localStorage.setItem('rc_key', passVal);

                        document.getElementById('modal').style.display = 'none';
                        const msgInput = document.getElementById('message-input');
                        msgInput.disabled = false;
                        msgInput.focus();
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
                        for (let msg of event.messages) {
                            await renderMessage(msg);
                        }
                    } 
                    else if (event.type === 'Message') {
                        await renderMessage(event.data);
                    } 
                    else if (event.type === 'Typing') {
                        handleTypingEvent(event.username, event.is_typing);
                    }
                };
            }

            function showError(msg) {
                const errorDiv = document.getElementById('error-msg');
                errorDiv.innerText = msg;
                errorDiv.style.display = 'block';
            }

            async function encryptText(text) {
                const enc = new TextEncoder();
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const ciphertext = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, cryptoKey, enc.encode(text)
                );
                return {
                    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
                    iv: btoa(String.fromCharCode(...iv))
                };
            }

            async function decryptText(ciphertextB64, ivB64) {
                try {
                    const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
                    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
                    const decrypted = await crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: iv }, cryptoKey, ciphertext
                    );
                    return new TextDecoder().decode(decrypted);
                } catch (e) {
                    return "⚠️ [Decryption Failed - Invalid Passphrase]";
                }
            }

            async function send() {
                const input = document.getElementById('message-input');
                const rawText = input.value.trim();
                if (!rawText || !ws) return;

                notifyTyping(false);
                const encrypted = await encryptText(rawText);
                ws.send(JSON.stringify({
                    type: "Send",
                    ciphertext: encrypted.ciphertext,
                    iv: encrypted.iv
                }));
                input.value = '';
            }

            async function renderMessage(msg) {
                const box = document.getElementById('messages');
                const plaintext = await decryptText(msg.ciphertext, msg.iv);
                const initial = msg.username.charAt(0).toUpperCase();

                let parsedBody = DOMPurify.sanitize(marked.parse(plaintext));
                parsedBody = parsedBody.replace(
                    /(https?:\/\/[^\s<]+?\.(?:png|jpg|jpeg|gif|webp))/gi, 
                    '<img src="$1" loading="lazy" />'
                );
                parsedBody = parsedBody.replace(
                    /(https?:\/\/[^\s<]+?\.(?:mp4|webm|ogg))/gi, 
                    '<video controls src="$1"></video>'
                );

                const timeStr = new Date(msg.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                const card = `
                    <div class="msg-card">
                        <div class="avatar">${initial}</div>
                        <div class="msg-content">
                            <div class="msg-header">
                                <span class="username">${escapeHtml(msg.username)}</span>
                                <span class="timestamp">${timeStr}</span>
                            </div>
                            <div class="body">${parsedBody}</div>
                        </div>
                    </div>
                `;
                box.innerHTML += card;
                box.scrollTop = box.scrollHeight;
            }

            function updateUserList(users) {
                const list = document.getElementById('user-list');
                document.getElementById('user-count').innerText = users.length;
                list.innerHTML = '';
                users.forEach(u => {
                    list.innerHTML += `<li><span class="status-dot"></span>${escapeHtml(u)}</li>`;
                });
            }

            // Typing Indicator Logic
            function handleTypingEvent(user, isTyping) {
                if (user === myUsername) return;
                if (isTyping) activeTypers.add(user);
                else activeTypers.delete(user);

                const indicator = document.getElementById('typing-indicator');
                const typers = Array.from(activeTypers);
                if (typers.length === 0) {
                    indicator.innerText = '';
                } else if (typers.length === 1) {
                    indicator.innerText = `${typers[0]} is typing...`;
                } else {
                    indicator.innerText = `Several people are typing...`;
                }
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

            inputElem.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') send();
            });
            document.getElementById('username-input').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') attemptJoin();
            });
            document.getElementById('room-key').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') attemptJoin();
            });

            function escapeHtml(text) {
                return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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

    // 1. Initial Handshake & Username Uniqueness Validation
   // 1. Initial Handshake & Username Uniqueness Validation
    while let Some(Ok(Message::Text(text))) = receiver.next().await {
        if let Ok(ClientEvent::Join { username }) = serde_json::from_str(&text) {
            let username_trimmed = username.trim().to_string();
            
            // Scope the Mutex lock so it gets dropped BEFORE any .await calls
            let is_taken = {
                let users = state.users.lock().unwrap();
                users.values().any(|u| u.eq_ignore_ascii_case(&username_trimmed))
            };

            // Check if username is already taken by another connected user
            if is_taken {
                let err_evt = ServerEvent::JoinError { error: "Username is already taken! Please choose another.".into() };
                let _ = sender.send(Message::Text(serde_json::to_string(&err_evt).unwrap())).await;
                return;
            } else {
                // Lock again quickly just to insert
                {
                    let mut users = state.users.lock().unwrap();
                    users.insert(my_id, username_trimmed.clone());
                }
                
                my_username = username_trimmed;

                let success_evt = ServerEvent::JoinSuccess { username: my_username.clone() };
                let _ = sender.send(Message::Text(serde_json::to_string(&success_evt).unwrap())).await;
                
                // Broadcast list after lock release
                let users_snapshot = state.users.lock().unwrap().clone();
                broadcast_user_list(&state, &users_snapshot);
                break;
            }
        }
    }

    if my_username.is_empty() { return; }

    // 2. Send 24-hour cached encrypted history
    let history = {
        let msgs = state.messages.lock().unwrap();
        msgs.iter().cloned().collect::<Vec<_>>()
    };
    let history_event = ServerEvent::History { messages: history };
    let _ = sender.send(Message::Text(serde_json::to_string(&history_event).unwrap())).await;

    // Task A: Forward broadcast events to WS client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Task B: Receive incoming client actions (Messages & Typing Indicators)
    let state_clone = state.clone();
    let username_clone = my_username.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            if let Ok(event) = serde_json::from_str::<ClientEvent>(&text) {
                match event {
                    ClientEvent::Send { ciphertext, iv } => {
                        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        let msg = EncryptedMessage {
                            username: username_clone.clone(),
                            ciphertext,
                            iv,
                            timestamp,
                        };

                        {
                            let mut msgs = state_clone.messages.lock().unwrap();
                            msgs.push_back(msg.clone());
                        }

                        let evt = ServerEvent::Message(msg);
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    ClientEvent::Typing { is_typing } => {
                        let evt = ServerEvent::Typing { username: username_clone.clone(), is_typing };
                        let _ = state_clone.tx.send(serde_json::to_string(&evt).unwrap());
                    }
                    _ => {}
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Cleanup user on disconnect
    {
        let mut users = state.users.lock().unwrap();
        users.remove(&my_id);
        broadcast_user_list(&state, &users);
    }
}

fn broadcast_user_list(state: &AppState, users: &HashMap<usize, String>) {
    let user_names: Vec<String> = users.values().cloned().collect();
    let event = ServerEvent::UserList { users: user_names };
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = state.tx.send(json);
    }
}
