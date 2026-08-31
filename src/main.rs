use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel::<String>(100);

    let app = Router::new()
        .route("/", get(index))
        .route("/ws", get(move |ws| ws_handler(ws, tx)));

    // Railway sets the PORT variable automatically
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    
    println!("Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Rust Chat</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: system-ui, sans-serif; max-width: 600px; margin: 20px auto; padding: 0 10px; }
            #messages { border: 1px solid #ddd; border-radius: 8px; height: 300px; overflow-y: scroll; padding: 12px; margin-bottom: 12px; background: #fafafa; }
            .msg { margin-bottom: 8px; padding: 6px 10px; background: white; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
            .input-row { display: flex; gap: 8px; }
            input { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 6px; }
            button { padding: 10px 20px; background: #0066cc; color: white; border: none; border-radius: 6px; cursor: pointer; }
        </style>
    </head>
    <body>
        <h2>⚡ Lightning Fast Rust Chat</h2>
        <div id="messages"></div>
        <div class="input-row">
            <input id="input" type="text" placeholder="Type a message..." autofocus />
            <button onclick="send()">Send</button>
        </div>
        <script>
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${protocol}//${location.host}/ws`);
            
            ws.onmessage = (e) => {
                const msgBox = document.getElementById('messages');
                msgBox.innerHTML += `<div class="msg">${e.data}</div>`;
                msgBox.scrollTop = msgBox.scrollHeight;
            };

            function send() {
                const input = document.getElementById('input');
                if (input.value.trim() !== '') {
                    ws.send(input.value);
                    input.value = '';
                }
            }

            document.getElementById('input').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') send();
            });
        </script>
    </body>
    </html>
    "#)
}

async fn ws_handler(ws: WebSocketUpgrade, tx: broadcast::Sender<String>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, tx))
}

async fn handle_socket(mut socket: WebSocket, tx: broadcast::Sender<String>) {
    let mut rx = tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(msg))) = socket.recv().await {
            let _ = tx.send(msg);
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
