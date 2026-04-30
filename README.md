# Kitten RTSP Webcam Site

Simple public viewer + password-protected admin for adding/removing RTSP feeds.

## Stack
- Nginx reverse proxy (public entrypoint)
- Flask app for UI/auth/feed storage
- SQLite for feed metadata
- MediaMTX for RTSP -> HLS conversion
- Docker + docker-compose

## Run
Create a `.env` file with strong secrets:

```bash
SECRET_KEY=replace-with-a-long-random-value
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=pbkdf2:sha256:600000$...   # generated with Werkzeug
```

Generate a compatible password hash:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"
```

```bash
docker compose up --build -d
```

Open:
- Viewer: `http://localhost`
- Admin: `http://localhost/admin/login`

Admin credentials come from `.env` environment variables.

## Production notes (Nginx + Cloudflare)
- Nginx is included in `docker-compose.yml` and listens on port `80`.
- Point Cloudflare DNS for `kittens.cyberask.co.uk` to your VM public IP.
- Keep Cloudflare proxy enabled (orange cloud) and set SSL mode to `Full` (or `Full (strict)` if you later add origin certs).
- Change `SECRET_KEY` and `ADMIN_PASSWORD_HASH`.
- Expose only port `80` to the internet; Flask and MediaMTX stay internal to Docker network.

## Clean VM quick start
```bash
git clone <your-repo-url>
cd we_pet_cam_html
cp .env.example .env   # or create .env manually if you do not keep an example file
docker compose up --build -d
```

Allow inbound TCP `80` in the VM firewall/security group.

## RTSP playback details
Browsers cannot play RTSP directly. The viewer uses HLS (`.m3u8`) via MediaMTX.

You should proxy HLS requests from Flask to MediaMTX at reverse-proxy level:
- `/hls_proxy?src=rtsp://...` is proxied by the included Nginx service to MediaMTX.

A practical option is to configure Nginx to rewrite/feed through MediaMTX or use static paths in MediaMTX and save path names in DB.
