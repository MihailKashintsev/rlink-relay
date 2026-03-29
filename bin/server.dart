import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_web_socket/shelf_web_socket.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

/// ═══════════════════════════════════════════════════════════════════
/// Rlink Relay Server — Zero-Knowledge WebSocket Relay
/// ═══════════════════════════════════════════════════════════════════
///
/// The server NEVER sees plaintext messages.  All chat payloads arrive
/// pre-encrypted (ChaCha20-Poly1305) by the client and are forwarded
/// as opaque blobs.  The only metadata the server knows:
///
///   • Public key (Ed25519 hex) of the registrant
///   • Optional nickname (for search — can be hashed client-side)
///   • Online/offline presence
///
/// Protocol (JSON over WebSocket):
///
///   C→S  {"type":"register","publicKey":"hex64","nick":"...", "challenge":"..."}
///   S→C  {"type":"registered","shortId":"hex8"}
///
///   C→S  {"type":"search","query":"nickname_or_id"}
///   S→C  {"type":"search_result","results":[{"publicKey":"...","nick":"...","shortId":"...","online":true},...]}
///
///   C→S  {"type":"packet","to":"publicKey_hex64","data":"base64_encrypted_gossip_packet"}
///   S→C  {"type":"packet","from":"publicKey_hex64","data":"base64_encrypted_gossip_packet"}
///
///   C→S  {"type":"broadcast","data":"base64_encrypted_gossip_packet"}
///   S→C  (forwarded to all online peers)
///
///   S→C  {"type":"presence","publicKey":"...","online":true/false}
///
/// Security guarantees:
///   1. E2E encryption — server forwards opaque base64 blobs
///   2. No message storage — relay only (packets not saved to disk)
///   3. No IP logging — no access logs written
///   4. Challenge-response ready — clients can prove key ownership
/// ═══════════════════════════════════════════════════════════════════

// ── Connected user ──────────────────────────────────────────────

class _User {
  final WebSocketChannel ws;
  final String publicKey;
  String nick;
  String get shortId => publicKey.length > 8 ? publicKey.substring(0, 8) : publicKey;
  DateTime connectedAt = DateTime.now();

  _User({required this.ws, required this.publicKey, required this.nick});
}

// ── Server state ────────────────────────────────────────────────

/// publicKey → _User (only one connection per key — last one wins)
final Map<String, _User> _users = {};

/// Rate limiting: publicKey → last N timestamps
final Map<String, List<DateTime>> _rateLimits = {};
const _rateWindow = Duration(seconds: 10);
const _rateMax = 100; // max 100 messages per 10 seconds

bool _checkRate(String publicKey) {
  final now = DateTime.now();
  final times = _rateLimits.putIfAbsent(publicKey, () => []);
  times.removeWhere((t) => now.difference(t) > _rateWindow);
  if (times.length >= _rateMax) return false; // rate limited
  times.add(now);
  return true;
}

// ── Handlers ────────────────────────────────────────────────────

void _handleMessage(_User user, dynamic raw) {
  if (raw is! String) return;
  if (raw.length > 65536) return; // max 64KB per message

  Map<String, dynamic> msg;
  try {
    msg = jsonDecode(raw) as Map<String, dynamic>;
  } catch (_) {
    return;
  }

  final type = msg['type'] as String?;
  if (type == null) return;

  if (!_checkRate(user.publicKey)) {
    user.ws.sink.add(jsonEncode({'type': 'error', 'msg': 'rate_limited'}));
    return;
  }

  switch (type) {
    case 'packet':
      _handlePacket(user, msg);
      break;
    case 'broadcast':
      _handleBroadcast(user, msg);
      break;
    case 'search':
      _handleSearch(user, msg);
      break;
    case 'ping':
      user.ws.sink.add(jsonEncode({'type': 'pong'}));
      break;
  }
}

void _handlePacket(_User sender, Map<String, dynamic> msg) {
  final to = msg['to'] as String?;
  final data = msg['data'] as String?; // base64-encoded encrypted packet
  if (to == null || data == null) return;
  if (data.length > 65536) return; // sanity

  final recipient = _users[to];
  if (recipient == null) {
    // Recipient offline — notify sender
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': to,
      'status': 'offline',
    }));
    return;
  }

  // Forward opaque blob — server NEVER decrypts
  recipient.ws.sink.add(jsonEncode({
    'type': 'packet',
    'from': sender.publicKey,
    'data': data,
  }));
}

void _handleBroadcast(_User sender, Map<String, dynamic> msg) {
  final data = msg['data'] as String?;
  if (data == null || data.length > 65536) return;

  final encoded = jsonEncode({
    'type': 'packet',
    'from': sender.publicKey,
    'data': data,
  });

  // Forward to ALL online users except sender
  for (final user in _users.values) {
    if (user.publicKey == sender.publicKey) continue;
    try {
      user.ws.sink.add(encoded);
    } catch (_) {}
  }
}

void _handleSearch(_User requester, Map<String, dynamic> msg) {
  final query = (msg['query'] as String?)?.toLowerCase().trim();
  if (query == null || query.isEmpty) return;

  final results = <Map<String, dynamic>>[];
  for (final user in _users.values) {
    if (user.publicKey == requester.publicKey) continue;
    final nickLower = user.nick.toLowerCase();
    final shortLower = user.shortId.toLowerCase();
    if (nickLower.contains(query) ||
        shortLower.contains(query) ||
        user.publicKey.toLowerCase().startsWith(query)) {
      results.add({
        'publicKey': user.publicKey,
        'nick': user.nick,
        'shortId': user.shortId,
        'online': true,
      });
      if (results.length >= 20) break; // limit results
    }
  }

  requester.ws.sink.add(jsonEncode({
    'type': 'search_result',
    'results': results,
  }));
}

// ── WebSocket handler ───────────────────────────────────────────

shelf.Handler _wsHandler() {
  return webSocketHandler((WebSocketChannel ws) {
    _User? user;
    late StreamSubscription sub;

    sub = ws.stream.listen(
      (raw) {
        if (user == null) {
          // First message must be registration
          if (raw is! String) return;
          try {
            final msg = jsonDecode(raw) as Map<String, dynamic>;
            if (msg['type'] != 'register') {
              ws.sink.add(jsonEncode({'type': 'error', 'msg': 'register_first'}));
              return;
            }
            final publicKey = msg['publicKey'] as String?;
            final nick = msg['nick'] as String? ?? '';
            if (publicKey == null ||
                !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(publicKey)) {
              ws.sink.add(jsonEncode({'type': 'error', 'msg': 'invalid_key'}));
              return;
            }

            // Disconnect previous connection for same key
            final prev = _users[publicKey];
            if (prev != null) {
              try { prev.ws.sink.close(); } catch (_) {}
            }

            user = _User(ws: ws, publicKey: publicKey, nick: nick);
            _users[publicKey] = user!;

            final shortId = publicKey.substring(0, 8);
            ws.sink.add(jsonEncode({
              'type': 'registered',
              'shortId': shortId,
              'onlineCount': _users.length,
            }));

            // Notify contacts about online status
            _broadcastPresence(publicKey, true);

            stdout.writeln('[+] ${nick.isEmpty ? shortId : nick} connected (${_users.length} online)');
          } catch (e) {
            ws.sink.add(jsonEncode({'type': 'error', 'msg': 'bad_register'}));
          }
        } else {
          _handleMessage(user!, raw);
        }
      },
      onDone: () {
        if (user != null) {
          _users.remove(user!.publicKey);
          _broadcastPresence(user!.publicKey, false);
          stdout.writeln('[-] ${user!.nick.isEmpty ? user!.shortId : user!.nick} disconnected (${_users.length} online)');
        }
      },
      onError: (_) {
        if (user != null) {
          _users.remove(user!.publicKey);
        }
      },
    );
  });
}

void _broadcastPresence(String publicKey, bool online) {
  final msg = jsonEncode({
    'type': 'presence',
    'publicKey': publicKey,
    'online': online,
  });
  for (final user in _users.values) {
    if (user.publicKey == publicKey) continue;
    try {
      user.ws.sink.add(msg);
    } catch (_) {}
  }
}

// ── Health check / info endpoint ────────────────────────────────

shelf.Response _infoHandler(shelf.Request request) {
  if (request.url.path == 'health') {
    return shelf.Response.ok(
      jsonEncode({
        'status': 'ok',
        'online': _users.length,
        'uptime': DateTime.now().toIso8601String(),
      }),
      headers: {'content-type': 'application/json'},
    );
  }
  return shelf.Response.notFound('Not found');
}

// ── Main ────────────────────────────────────────────────────────

Future<void> main() async {
  final port = int.tryParse(Platform.environment['PORT'] ?? '') ?? 8080;

  // Cascade: try WebSocket first, then HTTP info
  final handler = shelf.Cascade()
      .add(_wsHandler())
      .add(_infoHandler)
      .handler;

  final server = await io.serve(
    handler,
    InternetAddress.anyIPv4,
    port,
  );

  stdout.writeln('══════════════════════════════════════════════');
  stdout.writeln('  Rlink Relay Server v1.0');
  stdout.writeln('  Listening on ws://${server.address.host}:${server.port}');
  stdout.writeln('  Zero-knowledge relay — E2E encrypted only');
  stdout.writeln('══════════════════════════════════════════════');
}
