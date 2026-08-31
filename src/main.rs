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
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const DEFAULT_PASSPHRASE: &str = "RUSTCORD_SERVER_GLOBAL_SECRET_KEY";
const GLOBAL_SALT: &[u8] = b"rust_cord_secure_salt_2026";
const HUB_ID: &str = "hub";
const MAX_MSGS_PER_CHANNEL: usize = 200;
const BROADCAST_CAP: usize = 8192;

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
struct ChannelInfo {
    id: String,
    name: String,
    kind: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct GroupInfo {
    id: String,
    name: String,
    owner: String,
    invite_code: String,
    text_channels: Vec<ChannelInfo>,
    voice_channels: Vec<ChannelInfo>,
    members: Vec<String>,
    close_votes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
enum ServerEvent {
    JoinSuccess { username: String },
    JoinError { error: String },
    History {
        username: String,
        group_id: String,
        channel_id: String,
        messages: Vec<ChatMessage>,
    },
    Message {
        group_id: String,
        channel_id: String,
        username: String,
        text: String,
        timestamp: u64,
    },
    UserList { users: Vec<String> },
    Typing {
        group_id: String,
        channel_id: String,
        username: String,
        is_typing: bool,
    },
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
    ScreenShareState {
        username: String,
        sharing: bool,
    },
    DeleteVoiceRoom { room_id: String },
    GroupList { username: String, groups: Vec<GroupInfo> },
    GroupCreated { group: GroupInfo },
    GroupUpdated { group: GroupInfo },
    GroupDeleted { group_id: String },
    InvitePreview {
        username: String,
        invite_code: String,
        group_id: String,
        group_name: String,
        member_count: usize,
        valid: bool,
    },
    ChannelViewers {
        group_id: String,
        channel_id: String,
        count: usize,
        viewers: Vec<String>,
    },
    CloseVoteUpdate {
        group_id: String,
        votes: Vec<String>,
        required: usize,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientEvent {
    Join { username: String },
    Send {
        group_id: String,
        channel_id: String,
        text: String,
    },
    Typing {
        group_id: String,
        channel_id: String,
        is_typing: bool,
    },
    ViewChannel {
        group_id: String,
        channel_id: String,
    },
    SwitchGroup { group_id: String },
    CreateGroup { name: String },
    JoinGroup { invite_code: String },
    PreviewInvite { invite_code: String },
    DeleteGroup { group_id: String },
    VoteCloseGroup { group_id: String, agree: bool },
    CreateChannel {
        group_id: String,
        name: String,
        kind: String,
    },
    VoiceSignal { target: String, signal: serde_json::Value },
    VoiceInvite { target: String, room_id: String },
    VoiceStateUpdate { room_id: Option<String> },
    Speaking { is_speaking: bool },
    ScreenShareState { sharing: bool },
    DeleteVoiceRoom { room_id: String },
}

#[derive(Clone, Debug)]
struct ChatGroup {
    name: String,
    owner: String,
    invite_code: String,
    text_channels: Vec<ChannelInfo>,
    voice_channels: Vec<ChannelInfo>,
    members: HashSet<String>,
    close_votes: HashSet<String>,
    messages: HashMap<String, VecDeque<StoredMessage>>,
}

#[derive(Clone, Debug, Default)]
struct ConnState {
    username: String,
    group_id: String,
    channel_id: String,
    member_of: HashSet<String>,
}

struct AppState {
    tx: broadcast::Sender<String>,
    users: Mutex<HashMap<usize, String>>,
    user_conns: Mutex<HashMap<String, usize>>,
    conn_states: Mutex<HashMap<usize, ConnState>>,
    voice_states: Mutex<HashMap<String, String>>,
    groups: Mutex<HashMap<String, ChatGroup>>,
    invite_index: Mutex<HashMap<String, String>>,
    hub_messages: Mutex<HashMap<String, VecDeque<StoredMessage>>>,
    cipher: Aes256Gcm,
}

fn derive_cipher(passphrase: &str) -> Aes256Gcm {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), GLOBAL_SALT, 100_000, &mut key_bytes);
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

fn rand_token(prefix: &str, len: usize) -> String {
    let mut out = prefix.to_string();
    for _ in 0..len {
        let idx = (OsRng.next_u32() % 36) as usize;
        let ch = "0123456789abcdefghijklmnopqrstuvwxyz".chars().nth(idx).unwrap();
        out.push(ch);
    }
    out
}

fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(24)
        .collect()
}

fn broadcast(state: &AppState, event: &ServerEvent) {
    if let Ok(json) = serde_json::to_string(event) {
        let _ = state.tx.send(json);
    }
}

fn send_to_user(state: &AppState, username: &str, event: &ServerEvent) {
    if state.user_conns.lock().unwrap().contains_key(username) {
        broadcast(state, event);
    }
}

fn group_info(id: &str, g: &ChatGroup) -> GroupInfo {
    GroupInfo {
        id: id.to_string(),
        name: g.name.clone(),
        owner: g.owner.clone(),
        invite_code: g.invite_code.clone(),
        text_channels: g.text_channels.clone(),
        voice_channels: g.voice_channels.clone(),
        members: g.members.iter().cloned().collect(),
        close_votes: g.close_votes.iter().cloned().collect(),
    }
}

fn user_groups(state: &AppState, username: &str) -> Vec<GroupInfo> {
    let groups = state.groups.lock().unwrap();
    let mut out = vec![hub_group_info(state)];
    for (id, g) in groups.iter() {
        if g.members.contains(username) {
            out.push(group_info(id, g));
        }
    }
    out
}

fn hub_group_info(state: &AppState) -> GroupInfo {
    let hub = state.hub_messages.lock().unwrap();
    let text_channels = vec![ChannelInfo {
        id: "general".into(),
        name: "general".into(),
        kind: "text".into(),
    }];
    drop(hub);
    GroupInfo {
        id: HUB_ID.into(),
        name: "Nimbus".into(),
        owner: "system".into(),
        invite_code: String::new(),
        text_channels,
        voice_channels: vec![ChannelInfo {
            id: "general".into(),
            name: "General VC".into(),
            kind: "voice".into(),
        }],
        members: state.users.lock().unwrap().values().cloned().collect(),
        close_votes: vec![],
    }
}

fn channel_viewers(state: &AppState, group_id: &str, channel_id: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    state
        .conn_states
        .lock()
        .unwrap()
        .values()
        .filter(|c| c.group_id == group_id && c.channel_id == channel_id)
        .filter_map(|c| {
            if seen.insert(c.username.clone()) {
                Some(c.username.clone())
            } else {
                None
            }
        })
        .collect()
}

fn broadcast_channel_viewers(state: &AppState, group_id: &str, channel_id: &str) {
    let viewers = channel_viewers(state, group_id, channel_id);
    broadcast(
        state,
        &ServerEvent::ChannelViewers {
            group_id: group_id.to_string(),
            channel_id: channel_id.to_string(),
            count: viewers.len(),
            viewers,
        },
    );
}

fn store_message(
    state: &AppState,
    group_id: &str,
    channel_id: &str,
    stored: StoredMessage,
) {
    if group_id == HUB_ID {
        let mut hub = state.hub_messages.lock().unwrap();
        let q = hub.entry(channel_id.to_string()).or_default();
        q.push_back(stored);
        if q.len() > MAX_MSGS_PER_CHANNEL {
            q.pop_front();
        }
    } else {
        let mut groups = state.groups.lock().unwrap();
        if let Some(g) = groups.get_mut(group_id) {
            let q = g.messages.entry(channel_id.to_string()).or_default();
            q.push_back(stored);
            if q.len() > MAX_MSGS_PER_CHANNEL {
                q.pop_front();
            }
        }
    }
}

fn get_history(
    state: &AppState,
    group_id: &str,
    channel_id: &str,
) -> Vec<ChatMessage> {
    if group_id == HUB_ID {
        state
            .hub_messages
            .lock()
            .unwrap()
            .get(channel_id)
            .map(|msgs| {
                msgs.iter()
                    .filter_map(|m| decrypt_stored(&state.cipher, m))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        state
            .groups
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|g| g.messages.get(channel_id))
            .map(|msgs| {
                msgs.iter()
                    .filter_map(|m| decrypt_stored(&state.cipher, m))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn delete_group(state: &AppState, group_id: &str) {
    let mut groups = state.groups.lock().unwrap();
    if let Some(g) = groups.remove(group_id) {
        state.invite_index.lock().unwrap().remove(&g.invite_code);
        drop(groups);

        let mut voice = state.voice_states.lock().unwrap();
        let prefix = format!("{group_id}:");
        let evicted: Vec<String> = voice
            .iter()
            .filter(|(_, r)| r.starts_with(&prefix))
            .map(|(u, _)| u.clone())
            .collect();
        voice.retain(|_, r| !r.starts_with(&prefix));
        drop(voice);

        for u in evicted {
            broadcast(
                state,
                &ServerEvent::VoiceStateUpdate {
                    username: u,
                    room_id: None,
                },
            );
        }

        {
            let mut conn = state.conn_states.lock().unwrap();
            for cs in conn.values_mut() {
                cs.member_of.remove(group_id);
                if cs.group_id == group_id {
                    cs.group_id = HUB_ID.into();
                    cs.channel_id = "general".into();
                }
            }
        }

        broadcast(state, &ServerEvent::GroupDeleted { group_id: group_id.to_string() });
    }
}

fn conn_in_group(state: &AppState, conn_id: usize, group_id: &str) -> bool {
    state
        .conn_states
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|c| c.group_id == group_id || c.member_of.contains(group_id))
        .unwrap_or(false)
}

fn should_send_event(state: &AppState, conn_id: usize, val: &serde_json::Value) -> bool {
    let event_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let users = state.users.lock().unwrap();
    let my_name = match users.get(&conn_id) {
        Some(n) => n.clone(),
        None => {
            return matches!(event_type, "JoinError");
        }
    };
    drop(users);

    match event_type {
        "JoinSuccess" | "History" => {
            let uname = val.get("username").and_then(|t| t.as_str()).unwrap_or("");
            my_name == uname
        }
        "JoinError" => !state.users.lock().unwrap().contains_key(&conn_id),
        "VoiceSignal" | "VoiceInvite" => {
            val.get("target").and_then(|t| t.as_str()) == Some(my_name.as_str())
        }
        "SpeakingUpdate" | "ScreenShareState" => {
            let speaker = val.get("username").and_then(|t| t.as_str()).unwrap_or("");
            if speaker == my_name {
                return false;
            }
            let voice = state.voice_states.lock().unwrap();
            let my_room = voice.get(&my_name);
            let their_room = voice.get(speaker);
            my_room.is_some() && my_room == their_room
        }
        "Message" | "Typing" | "ChannelViewers" => {
            let gid = val.get("group_id").and_then(|t| t.as_str()).unwrap_or("");
            conn_in_group(state, conn_id, gid)
        }
        "GroupCreated" | "GroupUpdated" | "GroupDeleted" | "CloseVoteUpdate" => {
            let gid = val.get("group_id")
                .or_else(|| val.get("group").and_then(|g| g.get("id")))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            if gid.is_empty() || gid == HUB_ID {
                true
            } else {
                state
                    .conn_states
                    .lock()
                    .unwrap()
                    .get(&conn_id)
                    .map(|c| c.member_of.contains(gid))
                    .unwrap_or(false)
            }
        }
        "GroupList" | "InvitePreview" => {
            val.get("username").and_then(|t| t.as_str()) == Some(my_name.as_str())
        }
        _ => true,
    }
}

#[tokio::main]
async fn main() {
    let passphrase =
        std::env::var("CHAT_PASSPHRASE").unwrap_or_else(|_| DEFAULT_PASSPHRASE.to_string());
    let cipher = derive_cipher(&passphrase);
    let (tx, _) = broadcast::channel::<String>(BROADCAST_CAP);

    let mut hub = HashMap::new();
    hub.insert("general".to_string(), VecDeque::new());

    let state = Arc::new(AppState {
        tx,
        users: Mutex::new(HashMap::new()),
        user_conns: Mutex::new(HashMap::new()),
        conn_states: Mutex::new(HashMap::new()),
        voice_states: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        invite_index: Mutex::new(HashMap::new()),
        hub_messages: Mutex::new(hub),
        cipher,
    });

    let state_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        loop {
            interval.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut hub = state_cleanup.hub_messages.lock().unwrap();
            for q in hub.values_mut() {
                q.retain(|m| now.saturating_sub(m.timestamp) < 86400);
            }
            drop(hub);
            let mut groups = state_cleanup.groups.lock().unwrap();
            for g in groups.values_mut() {
                for q in g.messages.values_mut() {
                    q.retain(|m| now.saturating_sub(m.timestamp) < 86400);
                }
            }
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
    let addr = format!("0.0.0.0:{port}");
    eprintln!("RustCord starting on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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

    let state_tx = state.clone();
    let mut send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg_str) => {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&msg_str) {
                        if !should_send_event(&state_tx, conn_id, &val) {
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
    });

    let state_rx = state.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                if let Ok(ev) = serde_json::from_str::<ClientEvent>(&text) {
                    handle_client_event(&state_rx, conn_id, &mut current_username, ev).await;
                }
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    cleanup_conn(&state, conn_id).await;
}

async fn cleanup_conn(state: &AppState, conn_id: usize) {
    let old_channel = state
        .conn_states
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|c| (c.group_id.clone(), c.channel_id.clone()));

    let mut users = state.users.lock().unwrap();
    let username = users.remove(&conn_id);
    state.conn_states.lock().unwrap().remove(&conn_id);
    drop(users);

    if let Some(username) = username {
        state.user_conns.lock().unwrap().remove(&username);
        let active: Vec<String> = state.users.lock().unwrap().values().cloned().collect();
        broadcast(state, &ServerEvent::UserList { users: active });

        if state.voice_states.lock().unwrap().remove(&username).is_some() {
            broadcast(
                state,
                &ServerEvent::VoiceStateUpdate {
                    username: username.clone(),
                    room_id: None,
                },
            );
        }

        let mut groups = state.groups.lock().unwrap();
        for g in groups.values_mut() {
            g.members.remove(&username);
            g.close_votes.remove(&username);
        }
    }

    if let Some((gid, cid)) = old_channel {
        broadcast_channel_viewers(state, &gid, &cid);
    }
}

async fn handle_client_event(
    state: &AppState,
    conn_id: usize,
    current_username: &mut Option<String>,
    ev: ClientEvent,
) {
    match ev {
        ClientEvent::Join { username } => join_user(state, conn_id, current_username, username).await,
        ClientEvent::Send {
            group_id,
            channel_id,
            text,
        } => {
            if let Some(name) = current_username.clone() {
                send_chat(state, &name, &group_id, &channel_id, text);
            }
        }
        ClientEvent::Typing {
            group_id,
            channel_id,
            is_typing,
        } => {
            if let Some(name) = current_username.clone() {
                broadcast(
                    state,
                    &ServerEvent::Typing {
                        group_id,
                        channel_id,
                        username: name,
                        is_typing,
                    },
                );
            }
        }
        ClientEvent::ViewChannel { group_id, channel_id } => {
            view_channel(state, conn_id, current_username.as_deref(), &group_id, &channel_id).await;
        }
        ClientEvent::SwitchGroup { group_id } => {
            switch_group(state, conn_id, current_username, &group_id).await;
        }
        ClientEvent::CreateGroup { name } => {
            if let Some(owner) = current_username.clone() {
                create_group(state, conn_id, &owner, name);
            }
        }
        ClientEvent::JoinGroup { invite_code } => {
            if let Some(name) = current_username.clone() {
                join_group(state, conn_id, &name, &invite_code, true);
            }
        }
        ClientEvent::PreviewInvite { invite_code } => {
            if let Some(name) = current_username.clone() {
                preview_invite(state, conn_id, &name, &invite_code);
            }
        }
        ClientEvent::DeleteGroup { group_id } => {
            if let Some(name) = current_username.clone() {
                delete_group_by_owner(state, &name, &group_id);
            }
        }
        ClientEvent::VoteCloseGroup { group_id, agree } => {
            if let Some(name) = current_username.clone() {
                vote_close_group(state, &name, &group_id, agree);
            }
        }
        ClientEvent::CreateChannel {
            group_id,
            name,
            kind,
        } => {
            if let Some(owner) = current_username.clone() {
                create_channel(state, &owner, &group_id, name, kind);
            }
        }
        ClientEvent::VoiceSignal { target, signal } => {
            if let Some(name) = current_username.clone() {
                send_to_user(
                    state,
                    &target,
                    &ServerEvent::VoiceSignal {
                        from: name,
                        target: target.clone(),
                        signal,
                    },
                );
            }
        }
        ClientEvent::VoiceInvite { target, room_id } => {
            if let Some(name) = current_username.clone() {
                send_to_user(
                    state,
                    &target,
                    &ServerEvent::VoiceInvite {
                        from: name,
                        target: target.clone(),
                        room_id,
                    },
                );
            }
        }
        ClientEvent::VoiceStateUpdate { room_id } => {
            if let Some(name) = current_username.clone() {
                let mut voice = state.voice_states.lock().unwrap();
                if let Some(ref r) = room_id {
                    voice.insert(name.clone(), r.clone());
                } else {
                    voice.remove(&name);
                }
                drop(voice);
                broadcast(
                    state,
                    &ServerEvent::VoiceStateUpdate {
                        username: name,
                        room_id,
                    },
                );
            }
        }
        ClientEvent::Speaking { is_speaking } => {
            if let Some(name) = current_username.clone() {
                broadcast(
                    state,
                    &ServerEvent::SpeakingUpdate {
                        username: name,
                        is_speaking,
                    },
                );
            }
        }
        ClientEvent::ScreenShareState { sharing } => {
            if let Some(name) = current_username.clone() {
                broadcast(
                    state,
                    &ServerEvent::ScreenShareState {
                        username: name,
                        sharing,
                    },
                );
            }
        }
        ClientEvent::DeleteVoiceRoom { room_id } => {
            let mut voice = state.voice_states.lock().unwrap();
            let removed: Vec<String> = voice
                .iter()
                .filter(|(_, r)| **r == room_id)
                .map(|(u, _)| u.clone())
                .collect();
            voice.retain(|_, r| r != &room_id);
            drop(voice);
            for u in removed {
                broadcast(
                    state,
                    &ServerEvent::VoiceStateUpdate {
                        username: u,
                        room_id: None,
                    },
                );
            }
            broadcast(state, &ServerEvent::DeleteVoiceRoom { room_id });
        }
    }
}

async fn join_user(
    state: &AppState,
    conn_id: usize,
    current_username: &mut Option<String>,
    username: String,
) {
    let clean = username.trim().to_string();
    if clean.is_empty() {
        broadcast(
            state,
            &ServerEvent::JoinError {
                error: "Username cannot be empty!".to_string(),
            },
        );
        return;
    }
    {
        let users = state.users.lock().unwrap();
        if users.values().any(|u| u.eq_ignore_ascii_case(&clean)) {
            broadcast(
                state,
                &ServerEvent::JoinError {
                    error: "Username is already taken!".to_string(),
                },
            );
            return;
        }
    }

    state.users.lock().unwrap().insert(conn_id, clean.clone());
    state.user_conns.lock().unwrap().insert(clean.clone(), conn_id);
    *current_username = Some(clean.clone());

    let mut member_of = HashSet::new();
    member_of.insert(HUB_ID.to_string());
    state.conn_states.lock().unwrap().insert(
        conn_id,
        ConnState {
            username: clean.clone(),
            group_id: HUB_ID.into(),
            channel_id: "general".into(),
            member_of,
        },
    );

    broadcast(
        state,
        &ServerEvent::JoinSuccess {
            username: clean.clone(),
        },
    );

    let active: Vec<String> = state.users.lock().unwrap().values().cloned().collect();
    broadcast(state, &ServerEvent::UserList { users: active });

    send_group_list(state, conn_id, &clean);

    send_history(state, conn_id, &clean, HUB_ID, "general");

    let voice = state.voice_states.lock().unwrap().clone();
    for (u, r) in voice {
        broadcast(
            state,
            &ServerEvent::VoiceStateUpdate {
                username: u,
                room_id: Some(r),
            },
        );
    }

    broadcast_channel_viewers(state, HUB_ID, "general");
}

fn send_group_list(state: &AppState, conn_id: usize, username: &str) {
    let groups = user_groups(state, username);
    if let Ok(json) = serde_json::to_string(&ServerEvent::GroupList {
        username: username.to_string(),
        groups,
    }) {
        let _ = state.tx.send(json);
    }
    let _ = conn_id;
}

fn send_history(state: &AppState, conn_id: usize, username: &str, group_id: &str, channel_id: &str) {
    let history = get_history(state, group_id, channel_id);
    if let Ok(json) = serde_json::to_string(&ServerEvent::History {
        username: username.to_string(),
        group_id: group_id.to_string(),
        channel_id: channel_id.to_string(),
        messages: history,
    }) {
        let _ = state.tx.send(json);
    }
    let _ = conn_id;
}

fn send_chat(state: &AppState, name: &str, group_id: &str, channel_id: &str, text: String) {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ref = Nonce::from_slice(&nonce);
    if let Ok(ct) = state.cipher.encrypt(nonce_ref, text.as_bytes()) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stored = StoredMessage {
            username: name.to_string(),
            ciphertext: BASE64_STANDARD.encode(ct),
            iv: BASE64_STANDARD.encode(nonce),
            timestamp: ts,
        };
        store_message(state, group_id, channel_id, stored);
        broadcast(
            state,
            &ServerEvent::Message {
                group_id: group_id.to_string(),
                channel_id: channel_id.to_string(),
                username: name.to_string(),
                text,
                timestamp: ts,
            },
        );
    }
}

async fn view_channel(
    state: &AppState,
    conn_id: usize,
    username: Option<&str>,
    group_id: &str,
    channel_id: &str,
) {
    let old = {
        let mut cs = state.conn_states.lock().unwrap();
        let Some(c) = cs.get_mut(&conn_id) else {
            return;
        };
        let old = (c.group_id.clone(), c.channel_id.clone());
        c.group_id = group_id.to_string();
        c.channel_id = channel_id.to_string();
        old
    };
    broadcast_channel_viewers(state, &old.0, &old.1);
    broadcast_channel_viewers(state, group_id, channel_id);
    if let Some(uname) = username {
        send_history(state, conn_id, uname, group_id, channel_id);
    }
}

async fn switch_group(
    state: &AppState,
    conn_id: usize,
    current_username: &Option<String>,
    group_id: &str,
) {
    let uname = match current_username {
        Some(u) => u.clone(),
        None => return,
    };
    {
        let mut cs = state.conn_states.lock().unwrap();
        let Some(c) = cs.get_mut(&conn_id) else {
            return;
        };
        if group_id != HUB_ID && !c.member_of.contains(group_id) {
            return;
        }
        c.group_id = group_id.to_string();
        c.channel_id = "general".to_string();
    }
    send_history(state, conn_id, &uname, group_id, "general");
    broadcast_channel_viewers(state, group_id, "general");
}

fn create_group(state: &AppState, conn_id: usize, owner: &str, name: String) {
    let clean = name.trim();
    if clean.is_empty() || clean.len() > 48 {
        return;
    }
    let id = rand_token("grp-", 8);
    let invite = rand_token("inv-", 10);
    let mut members = HashSet::new();
    members.insert(owner.to_string());
    let group = ChatGroup {
        name: clean.to_string(),
        owner: owner.to_string(),
        invite_code: invite.clone(),
        text_channels: vec![ChannelInfo {
            id: "general".into(),
            name: "general".into(),
            kind: "text".into(),
        }],
        voice_channels: vec![ChannelInfo {
            id: "general".into(),
            name: "General VC".into(),
            kind: "voice".into(),
        }],
        members,
        close_votes: HashSet::new(),
        messages: HashMap::new(),
    };
    state.groups.lock().unwrap().insert(id.clone(), group.clone());
    state
        .invite_index
        .lock()
        .unwrap()
        .insert(invite, id.clone());

    if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&conn_id) {
        cs.member_of.insert(id.clone());
    }

    broadcast(
        state,
        &ServerEvent::GroupCreated {
            group: group_info(&id, &group),
        },
    );
}

fn join_group(state: &AppState, conn_id: usize, username: &str, invite_code: &str, switch: bool) {
    let group_id = {
        let idx = state.invite_index.lock().unwrap();
        idx.get(invite_code).cloned()
    };
    let Some(gid) = group_id else { return };

    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(&gid) else {
            return;
        };
        g.members.insert(username.to_string());
        g.close_votes.remove(username);
        group_info(&gid, g)
    };

    if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&conn_id) {
        cs.member_of.insert(gid.clone());
        if switch {
            cs.group_id = gid.clone();
            cs.channel_id = "general".to_string();
        }
    }

    broadcast(state, &ServerEvent::GroupUpdated { group: updated.clone() });

    if switch {
        send_history(state, conn_id, username, &gid, "general");
        broadcast_channel_viewers(state, &gid, "general");
    }
}

fn preview_invite(state: &AppState, conn_id: usize, username: &str, invite_code: &str) {
    let idx = state.invite_index.lock().unwrap();
    let group_id = idx.get(invite_code).cloned();
    drop(idx);

    let preview = if let Some(gid) = group_id {
        let groups = state.groups.lock().unwrap();
        if let Some(g) = groups.get(&gid) {
            ServerEvent::InvitePreview {
                username: username.to_string(),
                invite_code: invite_code.to_string(),
                group_id: gid,
                group_name: g.name.clone(),
                member_count: g.members.len(),
                valid: true,
            }
        } else {
            ServerEvent::InvitePreview {
                username: username.to_string(),
                invite_code: invite_code.to_string(),
                group_id: String::new(),
                group_name: String::new(),
                member_count: 0,
                valid: false,
            }
        }
    } else {
        ServerEvent::InvitePreview {
            username: username.to_string(),
            invite_code: invite_code.to_string(),
            group_id: String::new(),
            group_name: String::new(),
            member_count: 0,
            valid: false,
        }
    };

    if let Ok(json) = serde_json::to_string(&preview) {
        let _ = state.tx.send(json);
    }
    let _ = conn_id;
}

fn delete_group_by_owner(state: &AppState, username: &str, group_id: &str) {
    if group_id == HUB_ID {
        return;
    }
    let is_owner = state
        .groups
        .lock()
        .unwrap()
        .get(group_id)
        .map(|g| g.owner == username)
        .unwrap_or(false);
    if is_owner {
        delete_group(state, group_id);
    }
}

fn vote_close_group(state: &AppState, username: &str, group_id: &str, agree: bool) {
    if group_id == HUB_ID {
        return;
    }
    let (required, votes, should_delete) = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if !g.members.contains(username) {
            return;
        }
        if agree {
            g.close_votes.insert(username.to_string());
        } else {
            g.close_votes.remove(username);
        }
        let required = g.members.len();
        let votes: Vec<String> = g.close_votes.iter().cloned().collect();
        let should_delete = required > 0 && votes.len() == required;
        (required, votes, should_delete)
    };

    broadcast(
        state,
        &ServerEvent::CloseVoteUpdate {
            group_id: group_id.to_string(),
            votes,
            required,
        },
    );

    if should_delete {
        delete_group(state, group_id);
    }
}

fn create_channel(state: &AppState, owner: &str, group_id: &str, name: String, kind: String) {
    if group_id == HUB_ID {
        return;
    }
    let clean = name.trim();
    if clean.is_empty() || clean.len() > 32 {
        return;
    }
    let id = slugify(clean);
    if id.is_empty() {
        return;
    }

    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if g.owner != owner {
            return;
        }
        let ch = ChannelInfo {
            id: id.clone(),
            name: clean.to_string(),
            kind: kind.clone(),
        };
        if kind == "voice" {
            if g.voice_channels.iter().any(|c| c.id == id) {
                return;
            }
            g.voice_channels.push(ch);
        } else {
            if g.text_channels.iter().any(|c| c.id == id) {
                return;
            }
            g.text_channels.push(ch);
            g.messages.entry(id).or_default();
        }
        group_info(group_id, g)
    };

    broadcast(state, &ServerEvent::GroupUpdated { group: updated });
}
