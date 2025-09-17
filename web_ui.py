"""Simple web chat interface for the Ollama model."""

from __future__ import annotations

import os
from aiohttp import web

from RQR_chat import init_messages, generate_response

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'/>
  <title>Ollama Chat</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }
    #chat-container { width: 60%; margin: 20px auto; background: #fff; border-radius: 8px; padding: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.3); }
    #chat { max-height: 400px; overflow-y: auto; padding: 10px; }
    .message { margin: 10px 0; }
    .user { text-align: right; }
    .bot { text-align: left; }
    .bubble { display: inline-block; padding: 8px 12px; border-radius: 15px; max-width: 80%; }
    .user .bubble { background: #d1e7dd; }
    .bot .bubble { background: #e2e3e5; }
    .time { display: block; font-size: 0.75em; color: #666; }
    #input-area { display: flex; margin-top: 10px; }
    #msg { flex: 1; padding: 10px; border-radius: 4px; border: 1px solid #ccc; }
    #sendBtn { padding: 10px 20px; margin-left: 10px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
    #sendBtn:disabled { background: #aaa; cursor: not-allowed; }
  </style>
</head>
<body>
  <div id='chat-container'>
    <h1>Ollama Web Chat</h1>
    <div id='chat'></div>
    <div id='input-area'>
      <input id='msg' type='text' placeholder='Escribe un mensaje'/>
      <button id='sendBtn' onclick='send()'>Enviar</button>
    </div>
  </div>
  <script>
  let isProcessing = false;
  async function send() {
    if (isProcessing) return;
    const input = document.getElementById('msg');
    const button = document.getElementById('sendBtn');
    const message = input.value.trim();
    if (!message) return;
    isProcessing = true;
    input.disabled = true;
    button.disabled = true;

    const chatDiv = document.getElementById('chat');
    chatDiv.innerHTML += `<div class='message user'><div class='bubble'><b>Tú:</b> ${message}<span class='time'>${new Date().toLocaleTimeString()}</span></div></div>`;
    chatDiv.scrollTop = chatDiv.scrollHeight;

    try {
      const res = await fetch('/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message})
      });
      const data = await res.json();
      chatDiv.innerHTML += `<div class='message bot'><div class='bubble'><b>Bot:</b> ${data.reply}<span class='time'>${new Date().toLocaleTimeString()}</span></div></div>`;
    } catch (e) {
      chatDiv.innerHTML += `<div class='message bot'><div class='bubble'><b>Bot:</b> Error: ${e}</div></div>`;
    } finally {
      isProcessing = false;
      input.disabled = false;
      button.disabled = false;
      input.value = '';
      input.focus();
      chatDiv.scrollTop = chatDiv.scrollHeight;
    }
  }

  document.getElementById('msg').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      send();
    }
  });
  </script>
</body>
</html>
"""

history = init_messages()


async def index(request: web.Request) -> web.Response:
    return web.Response(text=HTML_PAGE, content_type="text/html")


async def chat_handler(request: web.Request) -> web.Response:
    global history
    data = await request.json()
    message = data.get("message", "")
    reply, history = generate_response(message, history)
    return web.json_response({"reply": reply})


app = web.Application()
app.router.add_get("/", index)
app.router.add_post("/chat", chat_handler)


if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
