# Relay + TURN (Docker, Windows/Tuna)

This setup runs both:
- `relay` (WebSocket signaling/server logic) on `:8080`
- `turn` (coturn media relay) on `:3478` and `:5349`

## 0) Admin panel setup

The in-app Admin Panel (accessible via 16 taps on About screen) requires `RELAY_ADMIN_HASH` to be set.

Generate the hash of your chosen admin password:
```bash
echo -n "YourAdminPassword" | shasum -a 256 | awk '{print $1}'
```

Create a `.env` file next to `docker-compose.yml`:
```bash
cp .env.example .env
# Edit .env and set RELAY_ADMIN_HASH to the hash above
```

The **default** app admin password is `Misha0000ff2010` — its hash is already in `.env.example`.
Use the same password when prompted by the app.  
**Change this in production.**

## 1) Configure TURN credentials

Edit `turnserver.conf`:
- `realm=...`
- `user=rlink:change_me_strong_password`

Use a strong password in production.

## 2) Start services

```bash
docker compose up -d --build
```

## 3) Expose ports via Tuna

Forward these ports from your Windows host:
- `8080/tcp` (relay)
- `3478/tcp+udp` (TURN)
- `5349/tcp` (TURN over TLS)
- `49160-49200/udp` (TURN relay media)

Without UDP relay range (`49160-49200/udp`), TURN will not carry media reliably.

## 4) Run Flutter app with TURN defines

```bash
flutter run \
  --dart-define=TURN_HOST=<your_tuna_domain_or_ip> \
  --dart-define=TURN_USER=rlink \
  --dart-define=TURN_PASSWORD=<your_turn_password>
```

The app now uses STUN + your TURN server in `CallService`.

## 5) Quick checks

Health check relay:
```bash
curl http://<host>:8080/health
```

TURN check (inside container logs):
```bash
docker logs -f rlink-turn
```

If calls still fail, verify Tuna supports UDP forwarding for TURN relay ports.
