use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

// Struct to represent a chat message sent across WebSockets
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChatMessage {
    username: String,
    content: String,
    timestamp: String,
}

// Struct to represent server-to-client updates (chat messages or online user list)
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
enum ServerEvent {
    Message(ChatMessage),
    UserList { users: Vec<String> },
}

// Shared state across all connections
struct AppState {
    tx: broadcast::Sender<String>,
    users: Mutex<HashMap<usize, String>>,
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel::<String>(100);
    let state = Arc::new(AppState {
        tx,
        users: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/ws", get(move |ws| ws_handler(ws, state)));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    println!("Starting server on {}", addr);
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
        <!-- Marked.js for Markdown & DOMPurify for Security -->
        <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"></script>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: 'gg sans', 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #313338; color: #dbdee1; display: flex; height: 100vh; overflow: hidden; }
            
            /* Sidebar: Online Users */
            #sidebar { width: 240px; background: #2b2d31; display: flex; flex-direction: column; border-right: 1px solid #1f2023; }
            .sidebar-header { padding: 16px; font-weight: bold; color: #f2f5f7; border-bottom: 1px solid #1f2023; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
            #user-list { list-style: none; padding: 10px; overflow-y: auto; flex: 1; }
            #user-list li { display: flex; align-items: center; gap: 8px; padding: 8px; border-radius: 4px; font-size: 14px; color: #949ba4; }
            #user-list li:hover { background: #35373c; color: #dbdee1; }
            .status-dot { width: 10px; height: 10px; background: #23a55a; border-radius: 50%; display: inline-block; }

            /* Main Chat Area */
            #main { flex: 1; display: flex; flex-direction: column; background: #313338; }
            .chat-header { padding: 16px; background: #313338; border-bottom: 1px solid #1f2023; font-weight: bold; color: #f2f5f7; display: flex; align-items: center; gap: 8px; }
            #messages { flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 16px; }

            /* Message Cards */
            .msg-card { display: flex; gap: 14px; }
            .avatar { width: 40px; height: 40px; border-radius: 50%; background: #5865f2; color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; flex-shrink: 0; }
            .msg-content { display: flex; flex-direction: column; flex: 1; }
            .msg-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
            .username { font-weight: 600; color: #f2f5f7; font-size: 15px; }
            .timestamp { font-size: 12px; color: #949ba4; }
            .body { color: #dbdee1; font-size: 14px; line-height: 1.4; word-break: break-word; }

            /* Media Embeds */
            .body img { max-width: 400px; max-height: 300px; border-radius: 8px; margin-top: 8px; display: block; }
            .body video { max-width: 400px; max-height: 300px; border-radius: 8px; margin-top: 8px; display: block; }
            .body a { color: #00a8fc; text-decoration: none; }
            .body a:hover { text-decoration: underline; }
            .body code { background: #2b2d31; padding: 2px 4px; border-radius: 4px; font-family: monospace; font-size: 13px; }
            .body pre { background: #2b2d31; padding: 10px; border-radius: 6px; margin-top: 6px; overflow-x: auto; }

            /* Input Area */
            .input-container { padding: 0 20px 20px 20px; }
            .input-box { background: #383a40; border-radius: 8px; display: flex; align-items: center; padding: 0 16px; }
            #message-input { width: 100%; background: transparent; border: none; padding: 14px 0; color: #dbdee1; font-size: 14px; outline: none; }
            #message-input::placeholder { color: #80848e; }
            
            /* Login Modal */
            #modal { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 100; }
            .modal-box { background: #313338; padding: 32px; border-radius: 8px; width: 360px; text-align: center; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
            .modal-box h3 { color: #f2f5f7; margin-bottom: 8px; font-size: 20px; }
            .modal-box p { color: #949ba4; font-size: 14px; margin-bottom: 20px; }
            .modal-box input { width: 100%; padding: 10px; background: #1e1f22; border: 1px solid #111214; border-radius: 4px; color: white; margin-bottom: 16px; font-size: 14px; outline: none; }
            .modal-box button { width: 100%; padding: 12px; background: #5865f2; color: white; border: none; border-radius: 4px; font-weight: bold; font-size: 14px; cursor: pointer; }
            .modal-box button:hover { background: #4752c4; }
        </style>
    </head>
    <body>

        <!-- Login Overlay -->
        <div id="modal">
            <div class="modal-box">
                <h3>Welcome to RustCord</h3>
                <p>Enter a username to join the chat</p>
                <input id="username-input" type="text" placeholder="Username" autofocus />
                <button onclick="join()">Join Server</button>
            </div>
        </div>

        <!-- Sidebar: Online Users -->
        <div id="sidebar">
            <div class="sidebar-header">Online Users — <span id="user-count">0</span></div>
            <ul id="user-list"></ul>
        </div>

        <!-- Main Chat Area -->
        <div id="main">
            <div class="chat-header"># general</div>
            <div id="messages"></div>
            <div class="input-container">
                <div class="input-box">
                    <input id="message-input" type="text" placeholder="Message #general (Markdown, images & links supported)" disabled />
                </div>
            </div>
        </div>

        <script>
            let ws;
            let myUsername = "";

            function join() {
                const input = document.getElementById('username-input');
                if (!input.value.trim()) return;
                myUsername = input.value.trim();
                
                document.getElementById('modal').style.display = 'none';
                const msgInput = document.getElementById('message-input');
                msgInput.disabled = false;
                msgInput.focus();

                const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${protocol}//${location.host}/ws`);

                ws.onopen = () => {
                    // Send username on join
                    ws.send(JSON.stringify({ type: "Join", username: myUsername }));
                };

                ws.onmessage = (e) => {
                    const event = JSON.parse(e.data);
                    if (event.type === 'UserList') {
                        updateUserList(event.users);
                    } else if (event.type === 'Message') {
                        appendMessage(event.data);
                    }
                };
            }

            function updateUserList(users) {
                const list = document.getElementById('user-list');
                document.getElementById('user-count').innerText = users.length;
                list.innerHTML = '';
                users.forEach(u => {
                    list.innerHTML += `<li><span class="status-dot"></span>${escapeHtml(u)}</li>`;
                });
            }

            function appendMessage(msg) {
                const box = document.getElementById('messages');
                const initial = msg.username.charAt(0).toUpperCase();

                // 1. Sanitize raw HTML to prevent XSS attacks
                // 2. Parse Markdown bold, italic, codeblocks
                let parsedBody = DOMPurify.sanitize(marked.parse(msg.content));

                // 3. Auto-embed raw Image & Video URLs dynamically
                parsedBody = parsedBody.replace(
                    /(https?:\/\/[^\s<]+?\.(?:png|jpg|jpeg|gif|webp))/gi, 
                    '<img src="$1" loading="lazy" />'
                );
                parsedBody = parsedBody.replace(
                    /(https?:\/\/[^\s<]+?\.(?:mp4|webm|ogg))/gi, 
                    '<video controls src="$1"></video>'
                );

                const card = `
                    <div class="msg-card">
                        <div class="avatar">${initial}</div>
                        <div class="msg-content">
                            <div class="msg-header">
                                <span class="username">${escapeHtml(msg.username)}</span>
                                <span class="timestamp">${msg.timestamp}</span>
                            </div>
                            <div class="body">${parsedBody}</div>
                        </div>
                    </div>
                `;
                box.innerHTML += card;
                box.scrollTop = box.scrollHeight;
            }

            function send() {
                const input = document.getElementById('message-input');
                if (input.value.trim() !== '' && ws) {
                    ws.send(JSON.stringify({ type: "Message", content: input.value }));
                    input.value = '';
                }
            }

            document.getElementById('message-input').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') send();
            });
            document.getElementById('username-input').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') join();
            });

            function escapeHtml(text) {
                return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            }
        </script>
    </body>
    </html>
    "#)
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientEvent {
    Join { username: String },
    Message { content: String },
}

async fn ws_handler(ws: WebSocketUpgrade, state: Arc<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    static NEXT_USER_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let my_id = NEXT_USER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Read initial message to register username
    let mut username = format!("User {}", my_id);
    if let Some(Ok(Message::Text(text))) = receiver.next().await {
        if let Ok(ClientEvent::Join { username: u }) = serde_json::from_str(&text) {
            username = u;
        }
    }

    // Register active connection
    {
        let mut users = state.users.lock().unwrap();
        users.insert(my_id, username.clone());
        broadcast_user_list(&state, &users);
    }

    // Task 1: Receive incoming broadcast events and send to WebSocket client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Task 2: Listen for client chat messages
    let state_clone = state.clone();
    let username_clone = username.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            if let Ok(ClientEvent::Message { content }) = serde_json::from_str(&text) {
                let chat_msg = ChatMessage {
                    username: username_clone.clone(),
                    content,
                    timestamp: chrono_now_time(),
                };
                let event = ServerEvent::Message(chat_msg);
                let json = serde_json::to_string(&event).unwrap();
                let _ = state_clone.tx.send(json);
            }
        }
    });

    // Clean up when connection drops
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Remove user from state and broadcast updated online list
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

// Generate simple timestamp format
fn chrono_now_time() -> String {
    // Basic fallback without needing full external chrono library dependencies
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    format!("{:02}:{:02} UTC", hours, mins)
}
