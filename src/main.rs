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
const ROOM_TTL_SECS: u64 = 86400;
const ADMIN_SESSION_SECS: u64 = 600;
const DEFAULT_ADMIN_PASSWORD: &str = "1234";

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
struct AdminUserRoom {
    id: String,
    name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AdminUserRow {
    username: String,
    device_id: String,
    group_id: String,
    channel_id: String,
    in_voice: bool,
    voice_room: Option<String>,
    globally_muted: bool,
    rooms: Vec<AdminUserRoom>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AdminRoomRow {
    id: String,
    name: String,
    owner: String,
    members: Vec<String>,
    member_count: usize,
    active_members: usize,
    age_secs: u64,
    message_count: usize,
    invite_code: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AdminBanRow {
    username: String,
    device_id: String,
    room_ban: bool,
    reason: String,
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
        online_count: usize,
        created_at: u64,
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
    KickedFromGroup {
        username: String,
        group_id: String,
        group_name: String,
    },
    ModUpdate {
        username: String,
        group_id: String,
        force_muted: bool,
        force_deafened: bool,
        timeout_until: u64,
    },
    AdminAuthResult {
        username: String,
        success: bool,
        expires_at: u64,
        token: String,
    },
    AdminDashboard {
        username: String,
        expires_at: u64,
        token: String,
        active_users: Vec<AdminUserRow>,
        lifetime_user_count: usize,
        total_rooms: usize,
        inactive_rooms: usize,
        total_messages: u64,
        uptime_secs: u64,
        rooms: Vec<AdminRoomRow>,
        bans: Vec<AdminBanRow>,
    },
    AdminNavigate {
        username: String,
        group_id: String,
        channel_id: String,
    },
    UsernameChanged {
        username: String,
    },
    GlobalAdminAction {
        username: String,
        globally_muted: bool,
        room_banned: bool,
        banned: bool,
        reason: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientEvent {
    Join {
        username: String,
        device_id: String,
    },
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
    KickMember { group_id: String, target: String },
    ModMute {
        group_id: String,
        target: String,
        enabled: bool,
    },
    ModDeafen {
        group_id: String,
        target: String,
        enabled: bool,
    },
    ModTimeout {
        group_id: String,
        target: String,
        duration_secs: u64,
    },
    AdminAuth { password: String },
    AdminRefresh { token: String },
    AdminAction {
        token: String,
        action: String,
        target: String,
        device_id: Option<String>,
        group_id: Option<String>,
        value: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct ChatGroup {
    name: String,
    owner: String,
    invite_code: String,
    created_at: u64,
    text_channels: Vec<ChannelInfo>,
    voice_channels: Vec<ChannelInfo>,
    members: HashSet<String>,
    close_votes: HashSet<String>,
    messages: HashMap<String, VecDeque<StoredMessage>>,
}

#[derive(Clone, Debug)]
struct GlobalBan {
    username: Option<String>,
    device_id: Option<String>,
    room_ban: bool,
    reason: String,
}

#[derive(Clone, Debug, Default)]
struct ConnState {
    username: String,
    group_id: String,
    channel_id: String,
    device_id: String,
    member_of: HashSet<String>,
}

#[derive(Clone, Debug, Default)]
struct ModState {
    force_muted: bool,
    force_deafened: bool,
    timeout_until: u64,
}

#[derive(Clone, Debug)]
struct AdminSession {
    token: String,
    expires_at: u64,
}

struct AppState {
    tx: broadcast::Sender<String>,
    started_at: u64,
    admin_password: String,
    users: Mutex<HashMap<usize, String>>,
    user_conns: Mutex<HashMap<String, usize>>,
    conn_states: Mutex<HashMap<usize, ConnState>>,
    voice_states: Mutex<HashMap<String, String>>,
    groups: Mutex<HashMap<String, ChatGroup>>,
    invite_index: Mutex<HashMap<String, String>>,
    mod_states: Mutex<HashMap<String, HashMap<String, ModState>>>,
    hub_messages: Mutex<HashMap<String, VecDeque<StoredMessage>>>,
    lifetime_users: Mutex<HashSet<String>>,
    total_messages: Mutex<u64>,
    global_bans: Mutex<Vec<GlobalBan>>,
    global_mutes: Mutex<HashSet<String>>,
    room_banned_users: Mutex<HashSet<String>>,
    room_banned_devices: Mutex<HashSet<String>>,
    admin_sessions: Mutex<HashMap<usize, AdminSession>>,
    admin_auth_fails: Mutex<HashMap<usize, (u32, u64)>>,
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn is_group_owner(state: &AppState, group_id: &str, username: &str) -> bool {
    state
        .groups
        .lock()
        .unwrap()
        .get(group_id)
        .map(|g| g.owner == username)
        .unwrap_or(false)
}

fn mod_state_for(state: &AppState, group_id: &str, username: &str) -> ModState {
    let now = now_secs();
    state
        .mod_states
        .lock()
        .unwrap()
        .get(group_id)
        .and_then(|m| m.get(username))
        .cloned()
        .filter(|s| s.timeout_until == 0 || s.timeout_until > now)
        .unwrap_or_default()
}

fn is_timed_out(state: &AppState, group_id: &str, username: &str) -> bool {
    mod_state_for(state, group_id, username).timeout_until > now_secs()
}

fn send_mod_update(state: &AppState, group_id: &str, target: &str) {
    let ms = mod_state_for(state, group_id, target);
    let until = if ms.timeout_until > now_secs() {
        ms.timeout_until
    } else {
        0
    };
    send_to_user(
        state,
        target,
        &ServerEvent::ModUpdate {
            username: target.to_string(),
            group_id: group_id.to_string(),
            force_muted: ms.force_muted,
            force_deafened: ms.force_deafened,
            timeout_until: until,
        },
    );
}

fn send_mod_updates_for_user(state: &AppState, username: &str) {
    let groups: Vec<String> = state
        .mod_states
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, users)| users.contains_key(username))
        .map(|(gid, _)| gid.clone())
        .collect();
    for gid in groups {
        send_mod_update(state, &gid, username);
    }
}

fn disconnect_from_group_vc(state: &AppState, username: &str, group_id: &str) {
    let prefix = format!("{group_id}:");
    let mut voice = state.voice_states.lock().unwrap();
    if let Some(room) = voice.get(username) {
        if room.starts_with(&prefix) {
            voice.remove(username);
            drop(voice);
            broadcast(
                state,
                &ServerEvent::VoiceStateUpdate {
                    username: username.to_string(),
                    room_id: None,
                },
            );
            return;
        }
    }
}

fn kick_member_from_group(state: &AppState, actor: &str, group_id: &str, target: &str) {
    if group_id == HUB_ID || !is_group_owner(state, group_id, actor) || target == actor {
        return;
    }

    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get(group_id) else {
            return;
        };
        if g.owner == target {
            return;
        }
        g.name.clone()
    };

    disconnect_from_group_vc(state, target, group_id);

    if let Some(&conn_id) = state.user_conns.lock().unwrap().get(target) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&conn_id) {
            if cs.group_id == group_id {
                cs.group_id = HUB_ID.into();
                cs.channel_id = "general".into();
                send_history(state, conn_id, target, HUB_ID, "general");
            }
        }
    }

    send_to_user(
        state,
        target,
        &ServerEvent::KickedFromGroup {
            username: target.to_string(),
            group_id: group_id.to_string(),
            group_name: updated,
        },
    );
}

fn remove_member_from_group(state: &AppState, actor: &str, group_id: &str, target: &str) {
    if group_id == HUB_ID || !is_group_owner(state, group_id, actor) || target == actor {
        return;
    }

    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if g.owner == target {
            return;
        }
        g.members.remove(target);
        g.close_votes.remove(target);
        group_info(group_id, g)
    };

    if let Some(&conn_id) = state.user_conns.lock().unwrap().get(target) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&conn_id) {
            cs.member_of.remove(group_id);
        }
    }

    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .remove(target);

    kick_member_from_group(state, actor, group_id, target);
    broadcast(state, &ServerEvent::GroupUpdated { group: updated });
}

fn set_mod_mute(state: &AppState, actor: &str, group_id: &str, target: &str, enabled: bool) {
    if group_id == HUB_ID || !is_group_owner(state, group_id, actor) || target == actor {
        return;
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .entry(target.to_string())
        .or_default()
        .force_muted = enabled;
    send_mod_update(state, group_id, target);
}

fn set_mod_deafen(state: &AppState, actor: &str, group_id: &str, target: &str, enabled: bool) {
    if group_id == HUB_ID || !is_group_owner(state, group_id, actor) || target == actor {
        return;
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .entry(target.to_string())
        .or_default()
        .force_deafened = enabled;
    send_mod_update(state, group_id, target);
}

fn timeout_member(state: &AppState, actor: &str, group_id: &str, target: &str, duration_secs: u64) {
    if group_id == HUB_ID || duration_secs == 0 || duration_secs > 604_800 {
        return;
    }
    if !is_group_owner(state, group_id, actor) || target == actor {
        return;
    }

    {
        let mut mods = state.mod_states.lock().unwrap();
        let entry = mods.entry(group_id.to_string()).or_default();
        let ms = entry.entry(target.to_string()).or_default();
        ms.timeout_until = now_secs() + duration_secs;
        ms.force_muted = true;
        ms.force_deafened = true;
    }

    kick_member_from_group(state, actor, group_id, target);
    send_mod_update(state, group_id, target);
}

fn secure_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn admin_password() -> String {
    std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| DEFAULT_ADMIN_PASSWORD.to_string())
}

fn is_admin_session(state: &AppState, conn_id: usize) -> bool {
    let now = now_secs();
    state
        .admin_sessions
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|s| s.expires_at > now)
        .unwrap_or(false)
}

fn validate_admin_token(state: &AppState, conn_id: usize, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let now = now_secs();
    state
        .admin_sessions
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|s| s.expires_at > now && secure_eq(&s.token, token))
        .unwrap_or(false)
}

fn grant_admin_session(state: &AppState, conn_id: usize) -> (u64, String) {
    let exp = now_secs() + ADMIN_SESSION_SECS;
    let token = rand_token("tok-", 24);
    state.admin_sessions.lock().unwrap().insert(
        conn_id,
        AdminSession {
            token: token.clone(),
            expires_at: exp,
        },
    );
    state.admin_auth_fails.lock().unwrap().remove(&conn_id);
    (exp, token)
}

fn admin_auth_locked(state: &AppState, conn_id: usize) -> bool {
    let now = now_secs();
    state
        .admin_auth_fails
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|(_, until)| *until > now)
        .unwrap_or(false)
}

fn record_admin_auth_fail(state: &AppState, conn_id: usize) {
    let now = now_secs();
    let mut fails = state.admin_auth_fails.lock().unwrap();
    let entry = fails.entry(conn_id).or_insert((0, 0));
    entry.0 += 1;
    if entry.0 >= 5 {
        entry.1 = now + 300;
        entry.0 = 0;
    }
}

fn revoke_admin_session(state: &AppState, conn_id: usize) {
    state.admin_sessions.lock().unwrap().remove(&conn_id);
}

fn ban_reason(state: &AppState, username: &str, device_id: &str) -> Option<String> {
    for ban in state.global_bans.lock().unwrap().iter() {
        let user_match = ban
            .username
            .as_ref()
            .map(|u| u.eq_ignore_ascii_case(username))
            .unwrap_or(false);
        let device_match = ban
            .device_id
            .as_ref()
            .map(|d| d == device_id)
            .unwrap_or(false);
        if user_match || device_match {
            return Some(ban.reason.clone());
        }
    }
    None
}

fn is_room_banned(state: &AppState, username: &str, device_id: &str) -> bool {
    state
        .room_banned_users
        .lock()
        .unwrap()
        .iter()
        .any(|u| u.eq_ignore_ascii_case(username))
        || state.room_banned_devices.lock().unwrap().contains(device_id)
}

fn is_globally_muted(state: &AppState, username: &str) -> bool {
    state
        .global_mutes
        .lock()
        .unwrap()
        .iter()
        .any(|u| u.eq_ignore_ascii_case(username))
}

fn send_global_admin_action(state: &AppState, username: &str) {
    let device_id = state
        .user_conns
        .lock()
        .unwrap()
        .get(username)
        .and_then(|cid| {
            state
                .conn_states
                .lock()
                .unwrap()
                .get(cid)
                .map(|c| c.device_id.clone())
        })
        .unwrap_or_default();
    let banned = ban_reason(state, username, &device_id).is_some();
    send_to_user(
        state,
        username,
        &ServerEvent::GlobalAdminAction {
            username: username.to_string(),
            globally_muted: is_globally_muted(state, username),
            room_banned: is_room_banned(state, username, &device_id),
            banned,
            reason: ban_reason(state, username, &device_id).unwrap_or_default(),
        },
    );
}

fn disconnect_user(state: &AppState, username: &str, reason: &str) {
    send_to_user(
        state,
        username,
        &ServerEvent::JoinError {
            error: reason.to_string(),
        },
    );
}

fn count_group_messages(g: &ChatGroup) -> usize {
    g.messages.values().map(|q| q.len()).sum()
}

fn active_members_in_group(state: &AppState, members: &HashSet<String>) -> usize {
    state
        .users
        .lock()
        .unwrap()
        .values()
        .filter(|u| members.contains(*u))
        .count()
}

fn notify_admin_dashboards(state: &AppState) {
    let now = now_secs();
    let sessions: Vec<(usize, String, String)> = {
        let admin = state.admin_sessions.lock().unwrap();
        let users = state.users.lock().unwrap();
        admin
            .iter()
            .filter(|(_, s)| s.expires_at > now)
            .filter_map(|(cid, s)| {
                users
                    .get(cid)
                    .map(|u| (*cid, u.clone(), s.token.clone()))
            })
            .collect()
    };
    for (conn_id, username, token) in sessions {
        if let Some(dash) = build_admin_dashboard(state, conn_id, &username, &token) {
            send_to_user(state, &username, &dash);
        }
    }
}

fn build_admin_dashboard(state: &AppState, conn_id: usize, username: &str, token: &str) -> Option<ServerEvent> {
    if !validate_admin_token(state, conn_id, token) {
        return None;
    }
    let expires_at = state
        .admin_sessions
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|s| s.expires_at)?;
    let now = now_secs();
    let voice = state.voice_states.lock().unwrap().clone();
    let global_mutes = state.global_mutes.lock().unwrap().clone();
    let groups_snap = state.groups.lock().unwrap().clone();

    let active_users: Vec<AdminUserRow> = state
        .conn_states
        .lock()
        .unwrap()
        .values()
        .map(|c| {
            let mut rooms = Vec::new();
            for rid in &c.member_of {
                if rid == HUB_ID {
                    continue;
                }
                if let Some(g) = groups_snap.get(rid) {
                    rooms.push(AdminUserRoom {
                        id: rid.clone(),
                        name: g.name.clone(),
                    });
                }
            }
            AdminUserRow {
                username: c.username.clone(),
                device_id: c.device_id.clone(),
                group_id: c.group_id.clone(),
                channel_id: c.channel_id.clone(),
                in_voice: voice.contains_key(&c.username),
                voice_room: voice.get(&c.username).cloned(),
                globally_muted: global_mutes
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(&c.username)),
                rooms,
            }
        })
        .collect();

    let online = state
        .users
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect::<HashSet<_>>();
    let mut rooms = Vec::new();
    let mut inactive_rooms = 0usize;
    for (id, g) in groups_snap.iter() {
        let active = g.members.iter().filter(|m| online.contains(*m)).count();
        if active == 0 {
            inactive_rooms += 1;
        }
        rooms.push(AdminRoomRow {
            id: id.clone(),
            name: g.name.clone(),
            owner: g.owner.clone(),
            members: g.members.iter().cloned().collect(),
            member_count: g.members.len(),
            active_members: active,
            age_secs: now.saturating_sub(g.created_at),
            message_count: count_group_messages(g),
            invite_code: g.invite_code.clone(),
        });
    }
    let total_rooms = rooms.len();

    let bans: Vec<AdminBanRow> = state
        .global_bans
        .lock()
        .unwrap()
        .iter()
        .map(|b| AdminBanRow {
            username: b.username.clone().unwrap_or_default(),
            device_id: b.device_id.clone().unwrap_or_default(),
            room_ban: b.room_ban,
            reason: b.reason.clone(),
        })
        .collect();

    Some(ServerEvent::AdminDashboard {
        username: username.to_string(),
        expires_at,
        token: token.to_string(),
        active_users,
        lifetime_user_count: state.lifetime_users.lock().unwrap().len(),
        total_rooms,
        inactive_rooms,
        total_messages: *state.total_messages.lock().unwrap(),
        uptime_secs: now.saturating_sub(state.started_at),
        rooms,
        bans,
    })
}

fn admin_set_mod_mute(state: &AppState, group_id: &str, target: &str, enabled: bool) {
    if group_id == HUB_ID || target.is_empty() {
        return;
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .entry(target.to_string())
        .or_default()
        .force_muted = enabled;
    send_mod_update(state, group_id, target);
}

fn admin_set_mod_deafen(state: &AppState, group_id: &str, target: &str, enabled: bool) {
    if group_id == HUB_ID || target.is_empty() {
        return;
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .entry(target.to_string())
        .or_default()
        .force_deafened = enabled;
    send_mod_update(state, group_id, target);
}

fn admin_timeout_member(state: &AppState, group_id: &str, target: &str, duration_secs: u64) {
    if group_id == HUB_ID || target.is_empty() || duration_secs == 0 || duration_secs > 604_800 {
        return;
    }
    {
        let mut mods = state.mod_states.lock().unwrap();
        let entry = mods.entry(group_id.to_string()).or_default();
        let ms = entry.entry(target.to_string()).or_default();
        ms.timeout_until = now_secs() + duration_secs;
        ms.force_muted = true;
        ms.force_deafened = true;
    }
    admin_kick_from_room(state, group_id, target);
    send_mod_update(state, group_id, target);
}

fn admin_ensure_member(state: &AppState, group_id: &str, username: &str) {
    if group_id == HUB_ID || username.is_empty() {
        return;
    }
    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        g.members.insert(username.to_string());
        g.close_votes.remove(username);
        group_info(group_id, g)
    };
    if let Some(&cid) = state.user_conns.lock().unwrap().get(username) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&cid) {
            cs.member_of.insert(group_id.to_string());
        }
        send_group_list(state, cid, username);
    }
    broadcast(
        state,
        &ServerEvent::GroupUpdated {
            group: updated,
        },
    );
}

fn admin_force_join_room(state: &AppState, group_id: &str, target: &str) {
    if group_id == HUB_ID || target.is_empty() {
        return;
    }
    admin_ensure_member(state, group_id, target);
    if let Some(&cid) = state.user_conns.lock().unwrap().get(target) {
        {
            let mut cs = state.conn_states.lock().unwrap();
            let Some(c) = cs.get_mut(&cid) else {
                return;
            };
            c.group_id = group_id.to_string();
            c.channel_id = "general".to_string();
        }
        send_history(state, cid, target, group_id, "general");
        broadcast_channel_viewers(state, group_id, "general");
    }
}

fn admin_remove_from_room(state: &AppState, group_id: &str, target: &str) {
    if group_id == HUB_ID || target.is_empty() {
        return;
    }
    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if g.owner == target {
            return;
        }
        g.members.remove(target);
        g.close_votes.remove(target);
        group_info(group_id, g)
    };
    disconnect_from_group_vc(state, target, group_id);
    if let Some(&cid) = state.user_conns.lock().unwrap().get(target) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&cid) {
            cs.member_of.remove(group_id);
            if cs.group_id == group_id {
                cs.group_id = HUB_ID.into();
                cs.channel_id = "general".into();
                send_history(state, cid, target, HUB_ID, "general");
            }
        }
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .remove(target);
    broadcast(
        state,
        &ServerEvent::GroupUpdated {
            group: updated,
        },
    );
}

fn admin_kick_from_room(state: &AppState, group_id: &str, target: &str) {
    if group_id == HUB_ID || target.is_empty() {
        return;
    }
    let group_name = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if g.owner == target {
            return;
        }
        g.members.remove(target);
        g.close_votes.remove(target);
        g.name.clone()
    };
    disconnect_from_group_vc(state, target, group_id);
    if let Some(&cid) = state.user_conns.lock().unwrap().get(target) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&cid) {
            cs.member_of.remove(group_id);
            if cs.group_id == group_id {
                cs.group_id = HUB_ID.into();
                cs.channel_id = "general".into();
                send_history(state, cid, target, HUB_ID, "general");
            }
        }
    }
    state
        .mod_states
        .lock()
        .unwrap()
        .entry(group_id.to_string())
        .or_default()
        .remove(target);
    send_to_user(
        state,
        target,
        &ServerEvent::KickedFromGroup {
            username: target.to_string(),
            group_id: group_id.to_string(),
            group_name,
        },
    );
    if let Some(g) = state.groups.lock().unwrap().get(group_id) {
        broadcast(
            state,
            &ServerEvent::GroupUpdated {
                group: group_info(group_id, g),
            },
        );
    }
}

fn admin_transfer_owner(state: &AppState, group_id: &str, new_owner: &str) {
    if group_id == HUB_ID || new_owner.is_empty() {
        return;
    }
    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        if !g.members.contains(new_owner) {
            return;
        }
        g.owner = new_owner.to_string();
        g.members.insert(new_owner.to_string());
        group_info(group_id, g)
    };
    if let Some(&cid) = state.user_conns.lock().unwrap().get(new_owner) {
        if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&cid) {
            cs.member_of.insert(group_id.to_string());
        }
    }
    broadcast(
        state,
        &ServerEvent::GroupUpdated {
            group: updated,
        },
    );
}

fn admin_rename_room(state: &AppState, group_id: &str, new_name: &str) {
    if group_id == HUB_ID {
        return;
    }
    let clean = new_name.trim();
    if clean.is_empty() || clean.len() > 48 {
        return;
    }
    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        g.name = clean.to_string();
        group_info(group_id, g)
    };
    broadcast(
        state,
        &ServerEvent::GroupUpdated {
            group: updated,
        },
    );
}

fn admin_reset_invite(state: &AppState, group_id: &str) {
    if group_id == HUB_ID {
        return;
    }
    let updated = {
        let mut groups = state.groups.lock().unwrap();
        let Some(g) = groups.get_mut(group_id) else {
            return;
        };
        let mut idx = state.invite_index.lock().unwrap();
        idx.remove(&g.invite_code);
        let invite = rand_token("inv-", 10);
        g.invite_code = invite.clone();
        idx.insert(invite, group_id.to_string());
        group_info(group_id, g)
    };
    broadcast(
        state,
        &ServerEvent::GroupUpdated {
            group: updated,
        },
    );
}

fn admin_clear_messages(state: &AppState, group_id: &str, channel_id: Option<&str>) {
    if group_id == HUB_ID {
        let mut hub = state.hub_messages.lock().unwrap();
        if let Some(cid) = channel_id {
            hub.remove(cid);
        } else {
            hub.clear();
        }
        return;
    }
    let mut groups = state.groups.lock().unwrap();
    let Some(g) = groups.get_mut(group_id) else {
        return;
    };
    if let Some(cid) = channel_id {
        g.messages.remove(cid);
    } else {
        g.messages.clear();
    }
}

fn admin_rename_user(state: &AppState, old: &str, new: &str) {
    let new = new.trim();
    if new.is_empty() || new.len() > 32 {
        return;
    }
    let Some((conn_id, old_exact)) = {
        let users = state.users.lock().unwrap();
        if users.values().any(|u| u.eq_ignore_ascii_case(new)) {
            return;
        }
        users
            .iter()
            .find(|(_, u)| u.eq_ignore_ascii_case(old))
            .map(|(cid, u)| (*cid, u.clone()))
    } else {
        return;
    };
    if old_exact.eq_ignore_ascii_case(new) {
        return;
    }

    state.users.lock().unwrap().insert(conn_id, new.to_string());
    state.user_conns.lock().unwrap().remove(&old_exact);
    state.user_conns.lock().unwrap().insert(new.to_string(), conn_id);

    if let Some(cs) = state.conn_states.lock().unwrap().get_mut(&conn_id) {
        cs.username = new.to_string();
    }

    if let Some(room) = state.voice_states.lock().unwrap().remove(&old_exact) {
        state.voice_states.lock().unwrap().insert(new.to_string(), room);
    }

    for g in state.groups.lock().unwrap().values_mut() {
        if g.members.remove(&old_exact) {
            g.members.insert(new.to_string());
        }
        if g.owner == old_exact {
            g.owner = new.to_string();
        }
        if g.close_votes.remove(&old_exact) {
            g.close_votes.insert(new.to_string());
        }
        for msgs in g.messages.values_mut() {
            for m in msgs.iter_mut() {
                if m.username == old_exact {
                    m.username = new.to_string();
                }
            }
        }
    }

    for msgs in state.hub_messages.lock().unwrap().values_mut() {
        for m in msgs.iter_mut() {
            if m.username == old_exact {
                m.username = new.to_string();
            }
        }
    }

    for room_mods in state.mod_states.lock().unwrap().values_mut() {
        if let Some(ms) = room_mods.remove(&old_exact) {
            room_mods.insert(new.to_string(), ms);
        }
    }

    {
        let mutes = state.global_mutes.lock().unwrap().clone();
        state.global_mutes.lock().unwrap().clear();
        for u in mutes {
            if u.eq_ignore_ascii_case(&old_exact) {
                state.global_mutes.lock().unwrap().insert(new.to_string());
            } else {
                state.global_mutes.lock().unwrap().insert(u);
            }
        }
    }

    {
        let banned = state.room_banned_users.lock().unwrap().clone();
        state.room_banned_users.lock().unwrap().clear();
        for u in banned {
            if u.eq_ignore_ascii_case(&old_exact) {
                state
                    .room_banned_users
                    .lock()
                    .unwrap()
                    .insert(new.to_string());
            } else {
                state.room_banned_users.lock().unwrap().insert(u);
            }
        }
    }

    for ban in state.global_bans.lock().unwrap().iter_mut() {
        if ban
            .username
            .as_ref()
            .map(|u| u.eq_ignore_ascii_case(&old_exact))
            .unwrap_or(false)
        {
            ban.username = Some(new.to_string());
        }
    }

    state.lifetime_users.lock().unwrap().remove(&old_exact);
    state.lifetime_users.lock().unwrap().insert(new.to_string());

    let active: Vec<String> = state.users.lock().unwrap().values().cloned().collect();
    broadcast(state, &ServerEvent::UserList { users: active });
    send_to_user(
        state,
        new,
        &ServerEvent::UsernameChanged {
            username: new.to_string(),
        },
    );
    send_global_admin_action(state, new);
}

fn admin_follow_user(state: &AppState, admin_conn_id: usize, admin_name: &str, target: &str) {
    if target.is_empty() || admin_name.eq_ignore_ascii_case(target) {
        return;
    }
    let loc = state
        .conn_states
        .lock()
        .unwrap()
        .values()
        .find(|c| c.username.eq_ignore_ascii_case(target))
        .map(|c| (c.group_id.clone(), c.channel_id.clone()));
    let Some((gid, cid)) = loc else {
        return;
    };
    if gid != HUB_ID {
        admin_ensure_member(state, &gid, admin_name);
    }
    {
        let mut cs = state.conn_states.lock().unwrap();
        let Some(c) = cs.get_mut(&admin_conn_id) else {
            return;
        };
        c.group_id = gid.clone();
        c.channel_id = cid.clone();
    }
    send_history(state, admin_conn_id, admin_name, &gid, &cid);
    broadcast_channel_viewers(state, &gid, &cid);
    send_to_user(
        state,
        admin_name,
        &ServerEvent::AdminNavigate {
            username: admin_name.to_string(),
            group_id: gid,
            channel_id: cid,
        },
    );
}

fn handle_admin_action(
    state: &AppState,
    conn_id: usize,
    token: &str,
    actor: &str,
    action: &str,
    target: &str,
    device_id: Option<String>,
    group_id: Option<String>,
    value: Option<String>,
) {
    if !validate_admin_token(state, conn_id, token) {
        return;
    }
    let target = target.trim();
    let value = value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    match action {
        "ban_user" => {
            if target.is_empty() {
                return;
            }
            state.global_bans.lock().unwrap().push(GlobalBan {
                username: Some(target.to_string()),
                device_id: device_id.clone(),
                room_ban: false,
                reason: "Banned by admin".into(),
            });
            disconnect_user(state, target, "You have been banned.");
            send_global_admin_action(state, target);
        }
        "ban_device" => {
            if let Some(ref did) = device_id {
                state.global_bans.lock().unwrap().push(GlobalBan {
                    username: None,
                    device_id: Some(did.clone()),
                    room_ban: false,
                    reason: "Device banned by admin".into(),
                });
                let victims: Vec<String> = state
                    .conn_states
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|c| c.device_id == *did)
                    .map(|c| c.username.clone())
                    .collect();
                for u in victims {
                    disconnect_user(&state, &u, "This device has been banned.");
                    send_global_admin_action(&state, &u);
                }
            }
        }
        "room_ban_user" => {
            if target.is_empty() {
                return;
            }
            state
                .room_banned_users
                .lock()
                .unwrap()
                .insert(target.to_string());
            state.global_bans.lock().unwrap().push(GlobalBan {
                username: Some(target.to_string()),
                device_id: device_id.clone(),
                room_ban: true,
                reason: "Room banned by admin".into(),
            });
            send_global_admin_action(state, target);
        }
        "room_ban_device" => {
            if let Some(ref did) = device_id {
                state.room_banned_devices.lock().unwrap().insert(did.clone());
                state.global_bans.lock().unwrap().push(GlobalBan {
                    username: None,
                    device_id: Some(did.clone()),
                    room_ban: true,
                    reason: "Device room-banned by admin".into(),
                });
                let victims: Vec<String> = state
                    .conn_states
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|c| c.device_id == *did)
                    .map(|c| c.username.clone())
                    .collect();
                for u in victims {
                    send_global_admin_action(&state, &u);
                }
            }
        }
        "global_mute" => {
            if !target.is_empty() {
                state.global_mutes.lock().unwrap().insert(target.to_string());
                send_global_admin_action(state, target);
            }
        }
        "global_unmute" => {
            if !target.is_empty() {
                state.global_mutes.lock().unwrap().remove(target);
                send_global_admin_action(state, target);
            }
        }
        "unban_user" => {
            if !target.is_empty() {
                state.global_bans.lock().unwrap().retain(|b| {
                    b.username
                        .as_ref()
                        .map(|u| !u.eq_ignore_ascii_case(target))
                        .unwrap_or(true)
                });
                state.room_banned_users.lock().unwrap().remove(target);
                send_global_admin_action(state, target);
            }
        }
        "unban_device" => {
            if let Some(ref did) = device_id {
                state.global_bans.lock().unwrap().retain(|b| {
                    b.device_id.as_ref().map(|d| d != did).unwrap_or(true)
                });
                state.room_banned_devices.lock().unwrap().remove(did);
            }
        }
        "delete_room" => {
            if let Some(ref gid) = group_id {
                if gid != HUB_ID {
                    delete_group(state, gid);
                }
            }
        }
        "kick_user" => {
            if !target.is_empty() {
                disconnect_user(state, target, "Kicked by admin.");
            }
        }
        "rename_user" => {
            if target.is_empty() {
                return;
            }
            if let Some(ref new_name) = value {
                admin_rename_user(state, target, new_name);
            }
        }
        "rename_room" => {
            if let (Some(ref gid), Some(ref name)) = (group_id.as_ref(), value.as_ref()) {
                admin_rename_room(state, gid, name);
            }
        }
        "transfer_owner" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_transfer_owner(state, gid, target);
                }
            }
        }
        "force_join_room" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_force_join_room(state, gid, target);
                }
            }
        }
        "add_to_room" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_ensure_member(state, gid, target);
                }
            }
        }
        "remove_from_room" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_remove_from_room(state, gid, target);
                }
            }
        }
        "kick_from_room" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_kick_from_room(state, gid, target);
                }
            }
        }
        "reset_invite" => {
            if let Some(ref gid) = group_id {
                admin_reset_invite(state, gid);
            }
        }
        "clear_messages" => {
            if let Some(ref gid) = group_id {
                admin_clear_messages(state, gid, value.as_deref());
            }
        }
        "room_mute" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_set_mod_mute(state, gid, target, true);
                }
            }
        }
        "room_unmute" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_set_mod_mute(state, gid, target, false);
                }
            }
        }
        "room_deafen" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_set_mod_deafen(state, gid, target, true);
                }
            }
        }
        "room_undeafen" => {
            if let Some(ref gid) = group_id {
                if !target.is_empty() {
                    admin_set_mod_deafen(state, gid, target, false);
                }
            }
        }
        "room_timeout" => {
            if let (Some(ref gid), Some(ref dur)) = (group_id.as_ref(), value.as_ref()) {
                if !target.is_empty() {
                    if let Ok(secs) = dur.parse::<u64>() {
                        admin_timeout_member(state, gid, target, secs);
                    }
                }
            }
        }
        "follow_user" => {
            if !target.is_empty() {
                admin_follow_user(state, conn_id, actor, target);
            }
        }
        _ => {}
    }
    notify_admin_dashboards(state);
}

fn purge_expired_rooms(state: &AppState) {
    let now = now_secs();
    let expired: Vec<String> = state
        .groups
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, g)| now.saturating_sub(g.created_at) >= ROOM_TTL_SECS)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        delete_group(state, &id);
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

        state.mod_states.lock().unwrap().remove(group_id);

        broadcast(state, &ServerEvent::GroupDeleted { group_id: group_id.to_string() });
        notify_admin_dashboards(state);
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
        "GroupList" | "InvitePreview" | "KickedFromGroup" | "ModUpdate" | "GlobalAdminAction" => {
            val.get("username").and_then(|t| t.as_str()) == Some(my_name.as_str())
        }
        "AdminAuthResult" => {
            val.get("username").and_then(|t| t.as_str()) == Some(my_name.as_str())
        }
        "AdminDashboard" => {
            if val.get("username").and_then(|t| t.as_str()) != Some(my_name.as_str()) {
                return false;
            }
            let token = val.get("token").and_then(|t| t.as_str()).unwrap_or("");
            validate_admin_token(state, conn_id, token)
        }
        "AdminNavigate" => {
            val.get("username").and_then(|t| t.as_str()) == Some(my_name.as_str())
        }
        "UsernameChanged" => {
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

    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admin_password = admin_password();

    let state = Arc::new(AppState {
        tx,
        started_at,
        admin_password,
        users: Mutex::new(HashMap::new()),
        user_conns: Mutex::new(HashMap::new()),
        conn_states: Mutex::new(HashMap::new()),
        voice_states: Mutex::new(HashMap::new()),
        groups: Mutex::new(HashMap::new()),
        invite_index: Mutex::new(HashMap::new()),
        mod_states: Mutex::new(HashMap::new()),
        hub_messages: Mutex::new(hub),
        lifetime_users: Mutex::new(HashSet::new()),
        total_messages: Mutex::new(0),
        global_bans: Mutex::new(Vec::new()),
        global_mutes: Mutex::new(HashSet::new()),
        room_banned_users: Mutex::new(HashSet::new()),
        room_banned_devices: Mutex::new(HashSet::new()),
        admin_sessions: Mutex::new(HashMap::new()),
        admin_auth_fails: Mutex::new(HashMap::new()),
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
            drop(groups);
            purge_expired_rooms(&state_cleanup);
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
    state.admin_sessions.lock().unwrap().remove(&conn_id);
    state.admin_auth_fails.lock().unwrap().remove(&conn_id);
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
            g.close_votes.remove(&username);
        }
    }

    if let Some((gid, cid)) = old_channel {
        broadcast_channel_viewers(state, &gid, &cid);
    }
    notify_admin_dashboards(state);
}

async fn handle_client_event(
    state: &AppState,
    conn_id: usize,
    current_username: &mut Option<String>,
    ev: ClientEvent,
) {
    match ev {
        ClientEvent::Join { username, device_id } => {
            join_user(state, conn_id, current_username, username, device_id).await;
        }
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
                notify_admin_dashboards(state);
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
        ClientEvent::KickMember { group_id, target } => {
            if let Some(name) = current_username.clone() {
                remove_member_from_group(state, &name, &group_id, &target);
            }
        }
        ClientEvent::ModMute {
            group_id,
            target,
            enabled,
        } => {
            if let Some(name) = current_username.clone() {
                set_mod_mute(state, &name, &group_id, &target, enabled);
            }
        }
        ClientEvent::ModDeafen {
            group_id,
            target,
            enabled,
        } => {
            if let Some(name) = current_username.clone() {
                set_mod_deafen(state, &name, &group_id, &target, enabled);
            }
        }
        ClientEvent::ModTimeout {
            group_id,
            target,
            duration_secs,
        } => {
            if let Some(name) = current_username.clone() {
                timeout_member(state, &name, &group_id, &target, duration_secs);
            }
        }
        ClientEvent::AdminAuth { password } => {
            if let Some(name) = current_username.clone() {
                if admin_auth_locked(state, conn_id) {
                    send_to_user(
                        state,
                        &name,
                        &ServerEvent::AdminAuthResult {
                            username: name.clone(),
                            success: false,
                            expires_at: 0,
                            token: String::new(),
                        },
                    );
                    return;
                }
                let ok = secure_eq(&password, &state.admin_password);
                let (exp, token) = if ok {
                    grant_admin_session(state, conn_id)
                } else {
                    record_admin_auth_fail(state, conn_id);
                    (0, String::new())
                };
                send_to_user(
                    state,
                    &name,
                    &ServerEvent::AdminAuthResult {
                        username: name.clone(),
                        success: ok,
                        expires_at: exp,
                        token: token.clone(),
                    },
                );
                if ok {
                    if let Some(dash) = build_admin_dashboard(state, conn_id, &name, &token) {
                        send_to_user(state, &name, &dash);
                    }
                }
            }
        }
        ClientEvent::AdminRefresh { token } => {
            if let Some(name) = current_username.clone() {
                if let Some(dash) = build_admin_dashboard(state, conn_id, &name, &token) {
                    send_to_user(state, &name, &dash);
                }
            }
        }
        ClientEvent::AdminAction {
            token,
            action,
            target,
            device_id,
            group_id,
            value,
        } => {
            if let Some(name) = current_username.clone() {
                handle_admin_action(
                    state,
                    conn_id,
                    &token,
                    &name,
                    &action,
                    &target,
                    device_id,
                    group_id,
                    value,
                );
            }
        }
    }
}

async fn join_user(
    state: &AppState,
    conn_id: usize,
    current_username: &mut Option<String>,
    username: String,
    device_id: String,
) {
    let clean = username.trim().to_string();
    let device_id = device_id.trim().to_string();
    if clean.is_empty() {
        broadcast(
            state,
            &ServerEvent::JoinError {
                error: "Username cannot be empty!".to_string(),
            },
        );
        return;
    }
    if device_id.is_empty() {
        broadcast(
            state,
            &ServerEvent::JoinError {
                error: "Invalid session.".to_string(),
            },
        );
        return;
    }
    if let Some(reason) = ban_reason(state, &clean, &device_id) {
        broadcast(
            state,
            &ServerEvent::JoinError {
                error: format!("Banned: {reason}"),
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

    state.lifetime_users.lock().unwrap().insert(clean.clone());
    state.users.lock().unwrap().insert(conn_id, clean.clone());
    state.user_conns.lock().unwrap().insert(clean.clone(), conn_id);
    *current_username = Some(clean.clone());

    let mut member_of = HashSet::new();
    member_of.insert(HUB_ID.to_string());
    {
        let groups = state.groups.lock().unwrap();
        for (id, g) in groups.iter() {
            if g.members.contains(&clean) {
                member_of.insert(id.clone());
            }
        }
    }
    state.conn_states.lock().unwrap().insert(
        conn_id,
        ConnState {
            username: clean.clone(),
            group_id: HUB_ID.into(),
            channel_id: "general".into(),
            device_id: device_id.clone(),
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
    send_mod_updates_for_user(state, &clean);
    send_global_admin_action(state, &clean);
    notify_admin_dashboards(state);
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
    if is_globally_muted(state, name) {
        return;
    }
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
        *state.total_messages.lock().unwrap() += 1;
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
        notify_admin_dashboards(state);
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
    notify_admin_dashboards(state);
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
    if group_id != HUB_ID && is_timed_out(state, group_id, &uname) {
        send_mod_update(state, group_id, &uname);
        return;
    }
    if group_id != HUB_ID {
        let device_id = state
            .conn_states
            .lock()
            .unwrap()
            .get(&conn_id)
            .map(|c| c.device_id.clone())
            .unwrap_or_default();
        if is_room_banned(state, &uname, &device_id) {
            return;
        }
    }
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
    notify_admin_dashboards(state);
}

fn create_group(state: &AppState, conn_id: usize, owner: &str, name: String) {
    let clean = name.trim();
    if clean.is_empty() || clean.len() > 48 {
        return;
    }
    let device_id = state
        .conn_states
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|c| c.device_id.clone())
        .unwrap_or_default();
    if is_room_banned(state, owner, &device_id) {
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
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
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
    notify_admin_dashboards(state);
}

fn join_group(state: &AppState, conn_id: usize, username: &str, invite_code: &str, switch: bool) {
    let group_id = {
        let idx = state.invite_index.lock().unwrap();
        idx.get(invite_code).cloned()
    };
    let Some(gid) = group_id else { return };

    if is_timed_out(state, &gid, username) {
        send_mod_update(state, &gid, username);
        return;
    }

    let device_id = state
        .conn_states
        .lock()
        .unwrap()
        .get(&conn_id)
        .map(|c| c.device_id.clone())
        .unwrap_or_default();
    if is_room_banned(state, username, &device_id) {
        return;
    }

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
    notify_admin_dashboards(state);
}

fn online_in_group(state: &AppState, members: &HashSet<String>) -> usize {
    state
        .users
        .lock()
        .unwrap()
        .values()
        .filter(|u| members.contains(*u))
        .count()
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
                online_count: online_in_group(state, &g.members),
                created_at: g.created_at,
                valid: true,
            }
        } else {
            ServerEvent::InvitePreview {
                username: username.to_string(),
                invite_code: invite_code.to_string(),
                group_id: String::new(),
                group_name: String::new(),
                member_count: 0,
                online_count: 0,
                created_at: 0,
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
            online_count: 0,
            created_at: 0,
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
