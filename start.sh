#!/bin/sh
# Single-container start: engine (uvicorn) in background, Telegram bot in
# foreground process group alongside it. The bot reaches the engine over
# loopback on the same port Render exposes.
PORT="${PORT:-10000}"
export ENGINE_URL="http://127.0.0.1:${PORT}"
export BOT_DB_PATH="${BOT_DB_PATH:-/tmp/bot.db}"
uvicorn main:app --host 0.0.0.0 --port "$PORT" &
sleep 3
python bot.py &
wait
