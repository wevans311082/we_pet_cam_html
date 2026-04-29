# Kitten RTSP Webcam Site

Simple public viewer + password-protected admin for adding/removing RTSP feeds.

## Stack
- Flask app for UI/auth/feed storage
- SQLite for feed metadata
- MediaMTX for RTSP -> HLS conversion
- Docker + docker-compose

## Run
```bash
docker compose up --build -d
```

Open:
- Viewer: `http://localhost:8000`
- Admin: `http://localhost:8000/admin/login`

Default admin credentials come from `docker-compose.yml` environment variables.

## Production notes (Nginx + Cloudflare)
- Put this behind your Nginx vhost for `kittens.hazzy.co.uk`.
- Enforce HTTPS at Nginx/Cloudflare.
- Change `SECRET_KEY` and `ADMIN_PASSWORD`.
- Restrict MediaMTX ports so only app/internal network can access it.

## RTSP playback details
Browsers cannot play RTSP directly. The viewer uses HLS (`.m3u8`) via MediaMTX.
You should proxy HLS requests from Flask to MediaMTX at reverse-proxy level:
- `/hls_proxy?src=rtsp://...` should map to MediaMTX dynamic path in your edge proxy.

A practical option is to configure Nginx to rewrite/feed through MediaMTX or use static paths in MediaMTX and save path names in DB.
