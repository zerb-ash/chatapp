use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use aes_gcm::aead::rand_core::RngCore;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const DEFAULT_PASSPHRASE: &str = "RUSTCORD_SERVER_GLOBAL_SECRET_KEY";
const GLOBAL_SALT: &[u8] = b"rust_cord_secure_salt_2026";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct StoredMessage {
    username: String,
    ciphertext: String,
    iv: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChatMessage {
    username: String,
    text: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
enum ServerEvent {
    JoinSuccess { username: String },
    JoinError { error: String },
    History { username: String, messages: Vec<ChatMessage> },
    Message {
        username: String,
        text: String,
        timestamp: u64,
    },
    UserList { users: Vec<String> },
    Typing { username: String, is_typing: bool },
    VoiceSignal {
        from: String,
        target: String,
        signal: serde_json::Value,
    },
    VoiceInvite {
        from: String,
        target: String,
        room_id: String,
    },
    VoiceStateUpdate {
        username: String,
        room_id: Option<String>,
    },
    SpeakingUpdate {
        username: String,
        is_speaking: bool,
    },
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
    Speaking { is_speaking: bool },
    DeleteVoiceRoom { room_id: String },
}

struct AppState {
    tx: broadcast::Sender<String>,
    users: Mutex<HashMap<usize, String>>,
    user_conns: Mutex<HashMap<String, usize>>,
    voice_states: Mutex<HashMap<String, String>>,
    messages: Mutex<VecDeque<StoredMessage>>,
    cipher: Aes256Gcm,
}

fn derive_cipher(passphrase: &str) -> Aes256Gcm {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        GLOBAL_SALT,
        100_000,
        &mut key_bytes,
    );
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    Aes256Gcm::new(key)
}

fn decrypt_stored(cipher: &Aes256Gcm, stored: &StoredMessage) -> Option<ChatMessage> {
    let ciphertext = BASE64_STANDARD.decode(&stored.ciphertext).ok()?;
    let iv_bytes = BASE64_STANDARD.decode(&stored.iv).ok()?;
    let nonce = Nonce::from_slice(&iv_bytes);
    let plain = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    let text = String::from_utf8(plain).ok()?;
    Some(ChatMessage {
        username: stored.username.clone(),
        text,
        timestamp: stored.timestamp,
    })
}

fn broadcast(state: &AppState, event: &ServerEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        let _ = state.tx.send(json);
    }
}

fn send_to_user(state: &AppState, username: &str, event: &ServerEvent) {
    let online = state.user_conns.lock().unwrap().contains_key(username);
    if online {
        broadcast(state, event);
    }
}

#[tokio::main]
async fn main() {
    let passphrase = std::env::var("CHAT_PASSPHRASE").unwrap_or_else(|_| DEFAULT_PASSPHRASE.to_string());
    let cipher = derive_cipher(&passphrase);
    let (tx, _) = broadcast::channel::<String>(512);

    let state = Arc::new(AppState {
        tx,
        users: Mutex::new(HashMap::new()),
        user_conns: Mutex::new(HashMap::new()),
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
        .route("/health", get(health))
        .route("/favicon.ico", get(favicon))
        .route("/ws", get({
            let state = state.clone();
            move |ws| ws_handler(ws, state.clone())
        }));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    eprintln!("RustCord starting on {addr}");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("RustCord listening on http://{addr}");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

async fn health() -> impl IntoResponse {
    "ok"
}

async fn favicon() -> impl IntoResponse {
    ([("cache-control", "no-store")], axum::http::StatusCode::NO_CONTENT)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("app.html"))
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
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(msg_str) => {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&msg_str) {
                                let event_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                let should_send = match event_type {
                                    "JoinSuccess" => {
                                        let uname = val.get("username").and_then(|t| t.as_str()).unwrap_or("");
                                        state_tx_task.users.lock().unwrap().get(&conn_id).map(|n| n == uname).unwrap_or(false)
                                    }
                                    "JoinError" => {
                                        !state_tx_task.users.lock().unwrap().contains_key(&conn_id)
                                    }
                                    "History" => {
                                        let for_user = val.get("username").and_then(|t| t.as_str()).unwrap_or("");
                                        state_tx_task.users.lock().unwrap().get(&conn_id).map(|n| n == for_user).unwrap_or(false)
                                    }
                                    "VoiceSignal" | "VoiceInvite" => {
                                        let target = val.get("target").and_then(|t| t.as_str()).unwrap_or("");
                                        let my_name = state_tx_task.users.lock().unwrap().get(&conn_id).cloned();
                                        my_name.map(|n| n == target).unwrap_or(false)
                                    }
                                    "SpeakingUpdate" => {
                                        let speaker = val.get("username").and_then(|t| t.as_str()).unwrap_or("");
                                        let is_speaking = val.get("is_speaking").and_then(|t| t.as_bool()).unwrap_or(false);
                                        let my_name = state_tx_task.users.lock().unwrap().get(&conn_id).cloned();
                                        let Some(my_name) = my_name else { continue; };
                                        if speaker == my_name { continue; }
                                        if !is_speaking {
                                            true
                                        } else {
                                            let voice = state_tx_task.voice_states.lock().unwrap();
                                            let my_room = voice.get(&my_name).cloned();
                                            let speaker_room = voice.get(speaker).cloned();
                                            my_room.is_some() && my_room == speaker_room
                                        }
                                    }
                                    _ => true,
                                };
                                if !should_send {
                                    continue;
                                }
                            }
                            if sender.send(Message::Text(msg_str)).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
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
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::JoinError {
                                        error: "Username cannot be empty!".to_string(),
                                    },
                                );
                                continue;
                            }

                            if users.values().any(|u| u.eq_ignore_ascii_case(&clean_name)) {
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::JoinError {
                                        error: "Username is already taken!".to_string(),
                                    },
                                );
                                continue;
                            }

                            users.insert(conn_id, clean_name.clone());
                            drop(users);

                            state_recv_task
                                .user_conns
                                .lock()
                                .unwrap()
                                .insert(clean_name.clone(), conn_id);
                            current_username = Some(clean_name.clone());

                            broadcast(
                                &state_recv_task,
                                &ServerEvent::JoinSuccess {
                                    username: clean_name.clone(),
                                },
                            );

                            let active_users: Vec<String> = state_recv_task
                                .users
                                .lock()
                                .unwrap()
                                .values()
                                .cloned()
                                .collect();
                            broadcast(
                                &state_recv_task,
                                &ServerEvent::UserList {
                                    users: active_users,
                                },
                            );

                            let msgs = state_recv_task.messages.lock().unwrap();
                            let history: Vec<ChatMessage> = msgs
                                .iter()
                                .filter_map(|m| decrypt_stored(&state_recv_task.cipher, m))
                                .collect();
                            drop(msgs);

                            broadcast(
                                &state_recv_task,
                                &ServerEvent::History {
                                    username: clean_name.clone(),
                                    messages: history,
                                },
                            );

                            let voice_states = state_recv_task.voice_states.lock().unwrap();
                            for (u, r) in voice_states.iter() {
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::VoiceStateUpdate {
                                        username: u.clone(),
                                        room_id: Some(r.clone()),
                                    },
                                );
                            }
                        }
                        ClientEvent::Send { text } => {
                            if let Some(ref name) = current_username {
                                let mut nonce_bytes = [0u8; 12];
                                OsRng.fill_bytes(&mut nonce_bytes);
                                let nonce = Nonce::from_slice(&nonce_bytes);

                                if let Ok(ciphertext_bytes) =
                                    state_recv_task.cipher.encrypt(nonce, text.as_bytes())
                                {
                                    let ciphertext_b64 = BASE64_STANDARD.encode(ciphertext_bytes);
                                    let iv_b64 = BASE64_STANDARD.encode(nonce_bytes);

                                    let timestamp = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();

                                    let stored = StoredMessage {
                                        username: name.clone(),
                                        ciphertext: ciphertext_b64,
                                        iv: iv_b64,
                                        timestamp,
                                    };

                                    let mut msgs = state_recv_task.messages.lock().unwrap();
                                    msgs.push_back(stored);
                                    if msgs.len() > 100 {
                                        msgs.pop_front();
                                    }
                                    drop(msgs);

                                    broadcast(
                                        &state_recv_task,
                                        &ServerEvent::Message {
                                            username: name.clone(),
                                            text,
                                            timestamp,
                                        },
                                    );
                                }
                            }
                        }
                        ClientEvent::Typing { is_typing } => {
                            if let Some(ref name) = current_username {
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::Typing {
                                        username: name.clone(),
                                        is_typing,
                                    },
                                );
                            }
                        }
                        ClientEvent::VoiceSignal { target, signal } => {
                            if let Some(ref name) = current_username {
                                send_to_user(
                                    &state_recv_task,
                                    &target,
                                    &ServerEvent::VoiceSignal {
                                        from: name.clone(),
                                        target: target.clone(),
                                        signal,
                                    },
                                );
                            }
                        }
                        ClientEvent::VoiceInvite { target, room_id } => {
                            if let Some(ref name) = current_username {
                                send_to_user(
                                    &state_recv_task,
                                    &target,
                                    &ServerEvent::VoiceInvite {
                                        from: name.clone(),
                                        target: target.clone(),
                                        room_id,
                                    },
                                );
                            }
                        }
                        ClientEvent::VoiceStateUpdate { room_id } => {
                            if let Some(ref name) = current_username {
                                let mut voice_states =
                                    state_recv_task.voice_states.lock().unwrap();
                                if let Some(ref r) = room_id {
                                    voice_states.insert(name.clone(), r.clone());
                                } else {
                                    voice_states.remove(name);
                                }
                                drop(voice_states);

                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::VoiceStateUpdate {
                                        username: name.clone(),
                                        room_id,
                                    },
                                );
                            }
                        }
                        ClientEvent::Speaking { is_speaking } => {
                            if let Some(ref name) = current_username {
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::SpeakingUpdate {
                                        username: name.clone(),
                                        is_speaking,
                                    },
                                );
                            }
                        }
                        ClientEvent::DeleteVoiceRoom { room_id } => {
                            let mut voice_states =
                                state_recv_task.voice_states.lock().unwrap();
                            let removed_users: Vec<String> = voice_states
                                .iter()
                                .filter(|(_, r)| **r == room_id)
                                .map(|(u, _)| u.clone())
                                .collect();
                            voice_states.retain(|_, r| r != &room_id);
                            drop(voice_states);

                            for u in removed_users {
                                broadcast(
                                    &state_recv_task,
                                    &ServerEvent::VoiceStateUpdate {
                                        username: u,
                                        room_id: None,
                                    },
                                );
                            }

                            broadcast(
                                &state_recv_task,
                                &ServerEvent::DeleteVoiceRoom { room_id },
                            );
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
        state.user_conns.lock().unwrap().remove(&username);
        let active_users: Vec<String> = users.values().cloned().collect();
        drop(users);

        broadcast(
            &state,
            &ServerEvent::UserList {
                users: active_users,
            },
        );

        let mut voice_states = state.voice_states.lock().unwrap();
        if voice_states.remove(&username).is_some() {
            drop(voice_states);
            broadcast(
                &state,
                &ServerEvent::VoiceStateUpdate {
                    username,
                    room_id: None,
                },
            );
        }
    }
}
