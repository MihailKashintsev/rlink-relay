import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_web_socket/shelf_web_socket.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'oauth.dart';

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
///   2. Offline mailbox stores only encrypted envelopes until recipient ACK
///   3. No IP logging — no access logs written
///   4. Challenge-response ready — clients can prove key ownership
///
/// Публичный каталог каналов (отступление от «полного» zero-knowledge):
///   • Клиент шлёт `channel_dir_put` с JSON-телом и Ed25519-подписью (ключ = adminId).
///   • Сервер проверяет подпись, хранит последнюю версию публичных каналов на диске.
///   • При `register` клиент получает `channel_dir_snapshot` — видны id, название,
///     username, universalCode и др. поля из подписанного JSON (метаданные публичного канала).
///   • Лимиты: размер снимка (`_channelDirSnapshotMaxEntries`, сортировка по updatedAt),
///     макс. длина подписываемого JSON (`_channelDirMaxPayloadChars`), отдельный rate limit put по adminId.
///   • `tombstones` в JSON растут при снятии канала с публикации — при необходимости можно
///     чистить старые ключи офлайн-скриптом (клиентам нужны только rev для антистейла).
///
/// Публичный каталог ботов (метаданные + ключи для E2E, как у presence):
///   • `bot_register_start` — JSON-подпись владельца (Ed25519), в payload указан будущий
///     `botPublicKey`; relay выдаёт `claimId`.
///   • `bot_claim` — после `register` **от ключа бота** с `claimId` (32 hex) или тем же
///     значением в поле `claimId`: короткий код `AAAA-BBBB-CCCC` (см. `claimCode` в ack);
///     relay создаёт запись, возвращает `apiToken` один раз (хеш хранится на диске).
///   • `bot_owner_list` / `bot_owner_patch` — подписанный JSON владельца: список своих
///     ботов и правка метаданных (имя, описание, avatar/banner URL); см. ack с `reqId`.
///   • `bot_info_get` + `reqId` / `handle` → `bot_info_result` (публичные поля + `commands`).
///   • `bot_commands_set` — либо `apiToken` + `commands` (сессия от ключа бота), либо
///     подписанный JSON владельца (`v`, `owner`, `botId`, `commands`, `ts`, `reqId`).
///   • `bot_dir_snapshot` после register; поиск дополняется зарегистрированными ботами.
/// ═══════════════════════════════════════════════════════════════════

// ── Connected user ──────────────────────────────────────────────

class _User {
  final WebSocketChannel ws;
  final String publicKey;
  String nick;
  String x25519Key;
  bool away = false; // true = backgrounded (don't show as online to others)
  String get shortId =>
      publicKey.length > 8 ? publicKey.substring(0, 8) : publicKey;
  DateTime connectedAt = DateTime.now();

  _User(
      {required this.ws,
      required this.publicKey,
      required this.nick,
      this.x25519Key = ''});
}

// ── Server state ────────────────────────────────────────────────

/// publicKey → _User (only one connection per key — last one wins)
final Map<String, _User> _users = {};

/// Rate limiting: publicKey → last N timestamps
final Map<String, List<DateTime>> _rateLimits = {};
const _rateWindow = Duration(seconds: 10);
const _rateMax =
    5000; // 5000 msgs / 10s — было 200, при таком лимите подписчики канала
// не получали полный набор chunks для фото/стикеров/видео (типичный пост
// ≈ сотни–тысячи 90-байтовых кусков). Каждый пакет очень маленький, поэтому
// поднятие лимита безопасно (≈5 кб/с per user в худшем случае).

/// Opaque encrypted blobs per Ed25519 identity (список каналов + метаданные синхронизации
/// аккаунта — клиент шифрует, relay не читает содержимое).
final Map<String, String> _accountBlobs = {};

/// Offline mailbox: recipientPublicKey -> relayMsgId -> envelope.
final Map<String, Map<String, Map<String, dynamic>>> _mailbox = {};
const _mailboxFile = 'relay_mailbox.json';
const _mailboxMaxPerRecipient = 600;
Timer? _mailboxPersistTimer;

/// Stored Web Push subscriptions by recipient public key.
final Map<String, List<Map<String, dynamic>>> _pushSubscriptions = {};
const _pushSubsFile = 'push_subscriptions.json';
const _pushCooldownSeconds = 12;
final Map<String, DateTime> _lastPushForRecipient = {};

final String _vapidPublicKey =
    (Platform.environment['VAPID_PUBLIC_KEY'] ?? '').trim();
final String _vapidPrivateKeyPem =
    (Platform.environment['VAPID_PRIVATE_KEY_PEM'] ?? '').trim();
final String _vapidSubject =
    (Platform.environment['VAPID_SUBJECT'] ?? 'mailto:admin@rlink.local')
        .trim();

// ── Публичный каталог каналов (подпись админа, персистентность) ──

final Map<String, Map<String, dynamic>> _channelDirectory = {};

/// После удаления канала из каталога — максимальный seen updatedAt (антиретрансляция).
final Map<String, int> _channelDirTombstones = {};
final Ed25519 _ed25519 = Ed25519();

const _channelDirFile = 'channel_directory.json';
const _channelDirMaxPayloadChars = 16384;
const _channelDirSnapshotMaxEntries = 4000;

/// Rate limit отдельно от общего flood: adminId → метки времени put.
final Map<String, List<DateTime>> _channelDirPutLimits = {};
const _channelDirPutWindow = Duration(minutes: 10);
const _channelDirPutMax = 180; // до 180 put на админа за 10 минут

bool _checkChannelDirPutRate(String adminId) {
  final now = DateTime.now();
  final times = _channelDirPutLimits.putIfAbsent(adminId, () => []);
  times.removeWhere((t) => now.difference(t) > _channelDirPutWindow);
  if (times.length >= _channelDirPutMax) return false;
  times.add(now);
  return true;
}

Future<bool> _verifyChannelDirSignature(
  String payloadJson,
  String signatureHex,
  String adminId,
) async {
  if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(adminId)) return false;
  if (signatureHex.length != 128) return false;
  try {
    final pubBytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      pubBytes[i] = int.parse(adminId.substring(i * 2, i * 2 + 2), radix: 16);
    }
    final sigBytes = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      sigBytes[i] =
          int.parse(signatureHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    final pubKey = SimplePublicKey(pubBytes, type: KeyPairType.ed25519);
    return await _ed25519.verify(
      utf8.encode(payloadJson),
      signature: Signature(sigBytes, publicKey: pubKey),
    );
  } catch (_) {
    return false;
  }
}

void _loadChannelDirectory() {
  try {
    final f = File(_channelDirFile);
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    final chans = decoded['channels'];
    final tombs = decoded['tombstones'];
    if (chans is Map) {
      chans.forEach((k, v) {
        if (k is String && v is Map) {
          _channelDirectory[k] = Map<String, dynamic>.from(v);
        }
      });
    }
    if (tombs is Map) {
      tombs.forEach((k, v) {
        if (k is String && v is num) {
          _channelDirTombstones[k] = v.toInt();
        }
      });
    }
    stdout.writeln(
      '[RLINK][Relay] Loaded ${_channelDirectory.length} public channel dir entries',
    );
  } catch (e) {
    stdout.writeln('[RLINK][Relay] channel_directory load: $e');
  }
}

void _persistChannelDirectory() {
  try {
    File(_channelDirFile).writeAsStringSync(jsonEncode({
      'channels': _channelDirectory,
      'tombstones': _channelDirTombstones,
    }));
  } catch (e) {
    stdout.writeln('[RLINK][Relay] channel_directory save: $e');
  }
}

// ── Публичный каталог ботов ─────────────────────────────────────

const _botDirFile = 'bot_directory.json';
const _botClaimTtl = Duration(minutes: 15);
const _botHandleMax = 32;
const _botHandleMin = 2;
const _botRegisterStartWindow = Duration(minutes: 10);
const _botRegisterStartMax = 60;
const _botOwnerListRateWindow = Duration(minutes: 1);
const _botOwnerListRateMax = 45;
const _botOwnerPatchRateWindow = Duration(minutes: 1);
const _botOwnerPatchRateMax = 45;
const _relayAdminFile = 'relay_admin.json';
String _relayAdminHash =
    (Platform.environment['RELAY_ADMIN_HASH'] ?? '').trim().toLowerCase();
final bool _verbosePacketLogs =
    (Platform.environment['RELAY_VERBOSE_PACKET_LOGS'] ?? '').trim() == '1';

int _forwardedPackets = 0;
int _forwardedBroadcastPackets = 0;
int _forwardedBlobs = 0;
int _droppedOversizePackets = 0;

final Map<String, Map<String, dynamic>> _botDirectory = {};
final Map<String, Map<String, dynamic>> _botClaims = {};
const _botActivityMaxEvents = 80;

/// Канонический короткий код `AAAA-BBBB-CCCC` (верхний регистр) → 32 hex claimId.
final Map<String, String> _botClaimCodeToClaimId = {};
final Map<String, List<DateTime>> _botRegisterStartLimits = {};
final Map<String, List<DateTime>> _botOwnerListRateLimits = {};
final Map<String, List<DateTime>> _botOwnerPatchRateLimits = {};

final Set<String> _reservedBotHandles = {
  'lib',
  'gigachat',
  'admin',
  'support',
  'rlink',
  'system',
  'botfather',
  'rendergames',
};

String _sha256HexUtf8(String s) {
  final d = sha256.convert(utf8.encode(s));
  return d.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

bool _isSha256Hex(String value) => RegExp(r'^[0-9a-f]{64}$').hasMatch(value);

void _loadRelayAdminConfig() {
  try {
    final f = File(_relayAdminFile);
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    final hash = _jsonString(decoded['adminHash']).toLowerCase().trim();
    if (_isSha256Hex(hash)) {
      _relayAdminHash = hash;
      stdout.writeln('[RLINK][Relay] Loaded persisted admin hash');
    }
  } catch (e) {
    stdout.writeln('[RLINK][Relay] relay_admin load: $e');
  }
}

void _persistRelayAdminConfig() {
  try {
    File(_relayAdminFile).writeAsStringSync(jsonEncode({
      'adminHash': _relayAdminHash,
      'updatedAt': DateTime.now().millisecondsSinceEpoch,
    }));
  } catch (e) {
    stdout.writeln('[RLINK][Relay] relay_admin save: $e');
  }
}

String _randomUrlToken() {
  final rnd = Random.secure();
  final bytes = List<int>.generate(32, (_) => rnd.nextInt(256));
  return base64Url.encode(bytes).replaceAll('=', '');
}

String _randomClaimId() {
  final rnd = Random.secure();
  final bytes = List<int>.generate(16, (_) => rnd.nextInt(256));
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Без 0/O/1/I/L/U — удобно диктовать и вводить; 12 символов ≈ 60 бит энтропии.
const _botClaimCodeAlphabet = '23456789ABCDEFGHJKMNPRSTWXYZ';

String _formatBotClaimCode12(String flat12Upper) {
  final s = flat12Upper.toUpperCase();
  return '${s.substring(0, 4)}-${s.substring(4, 8)}-${s.substring(8, 12)}';
}

/// Возвращает канонический `AAAA-BBBB-CCCC` или пустую строку.
String _normalizeBotClaimCodeInput(String raw) {
  var t = raw.trim().toUpperCase().replaceAll(RegExp(r'[\s_-]'), '');
  if (t.length != 12) return '';
  for (var i = 0; i < t.length; i++) {
    if (!_botClaimCodeAlphabet.contains(t[i])) return '';
  }
  return _formatBotClaimCode12(t);
}

String? _allocateUniqueBotClaimCode() {
  final rnd = Random.secure();
  for (var attempt = 0; attempt < 96; attempt++) {
    final buf = StringBuffer();
    for (var j = 0; j < 12; j++) {
      buf.write(
          _botClaimCodeAlphabet[rnd.nextInt(_botClaimCodeAlphabet.length)]);
    }
    final canonical = _formatBotClaimCode12(buf.toString());
    if (_botClaimCodeToClaimId.containsKey(canonical)) continue;
    var clash = false;
    for (final c in _botClaims.values) {
      if ((c['claimCode'] as String?)?.toUpperCase() == canonical) {
        clash = true;
        break;
      }
    }
    if (!clash) return canonical;
  }
  return null;
}

void _unlinkBotClaimCode(String? canonicalUpper) {
  if (canonicalUpper == null || canonicalUpper.isEmpty) return;
  _botClaimCodeToClaimId.remove(canonicalUpper.toUpperCase());
}

/// Удаляет заявку по claimId и снимает индекс короткого кода.
void _removeBotClaim(String claimIdLower) {
  final c = _botClaims.remove(claimIdLower);
  if (c == null) return;
  _unlinkBotClaimCode(c['claimCode'] as String?);
}

String? _normalizeBotHandle(String? raw) {
  if (raw == null) return null;
  var h = raw.trim().toLowerCase();
  if (h.startsWith('@')) h = h.substring(1);
  if (h.length < _botHandleMin || h.length > _botHandleMax) return null;
  if (!RegExp(r'^[a-z0-9_]+$').hasMatch(h)) return null;
  if (_reservedBotHandles.contains(h)) return null;
  return h;
}

bool _checkBotRegisterStartRate(String ownerPub) {
  final now = DateTime.now();
  final times = _botRegisterStartLimits.putIfAbsent(ownerPub, () => []);
  times.removeWhere((t) => now.difference(t) > _botRegisterStartWindow);
  if (times.length >= _botRegisterStartMax) return false;
  times.add(now);
  return true;
}

bool _checkBotOwnerListRate(String ownerPub) {
  final now = DateTime.now();
  final times = _botOwnerListRateLimits.putIfAbsent(ownerPub, () => []);
  times.removeWhere((t) => now.difference(t) > _botOwnerListRateWindow);
  if (times.length >= _botOwnerListRateMax) return false;
  times.add(now);
  return true;
}

bool _checkBotOwnerPatchRate(String ownerPub) {
  final now = DateTime.now();
  final times = _botOwnerPatchRateLimits.putIfAbsent(ownerPub, () => []);
  times.removeWhere((t) => now.difference(t) > _botOwnerPatchRateWindow);
  if (times.length >= _botOwnerPatchRateMax) return false;
  times.add(now);
  return true;
}

void _pruneExpiredBotClaims() {
  final now = DateTime.now().millisecondsSinceEpoch;
  final toRemove = <String>[];
  for (final e in _botClaims.entries) {
    final ts = (e.value['createdAt'] as num?)?.toInt() ?? 0;
    if (now - ts > _botClaimTtl.inMilliseconds) {
      toRemove.add(e.key);
    }
  }
  for (final id in toRemove) {
    _removeBotClaim(id);
  }
}

Future<bool> _verifyEd25519SignatureOnUtf8(
  String payloadUtf8,
  String signatureHex,
  String signerPubHex64,
) async {
  if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(signerPubHex64)) return false;
  if (signatureHex.length != 128) return false;
  try {
    final pubBytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      pubBytes[i] =
          int.parse(signerPubHex64.substring(i * 2, i * 2 + 2), radix: 16);
    }
    final sigBytes = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      sigBytes[i] =
          int.parse(signatureHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    final pubKey = SimplePublicKey(pubBytes, type: KeyPairType.ed25519);
    return await _ed25519.verify(
      utf8.encode(payloadUtf8),
      signature: Signature(sigBytes, publicKey: pubKey),
    );
  } catch (_) {
    return false;
  }
}

void _loadBotDirectory() {
  try {
    final f = File(_botDirFile);
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    final bots = decoded['bots'];
    if (bots is! List) return;
    for (final item in bots) {
      if (item is! Map) continue;
      final m = Map<String, dynamic>.from(item);
      final id = (m['botId'] as String?)?.toLowerCase();
      if (id == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(id)) continue;
      m['commands'] =
          _parseBotCommandsInput(m['commands']) ?? <Map<String, dynamic>>[];
      m['adminCode'] = _botAdminCode(id);
      m['activity'] = (m['activity'] is List) ? m['activity'] : <dynamic>[];
      _botDirectory[id] = m;
    }
    stdout.writeln(
      '[RLINK][Relay] Loaded ${_botDirectory.length} bot directory entries',
    );
  } catch (e) {
    stdout.writeln('[RLINK][Relay] bot_directory load: $e');
  }
}

void _persistBotDirectory() {
  try {
    final list = _botDirectory.values.toList();
    File(_botDirFile).writeAsStringSync(jsonEncode({'bots': list}));
  } catch (e) {
    stdout.writeln('[RLINK][Relay] bot_directory save: $e');
  }
}

void _sendBotDirSnapshot(WebSocketChannel ws) {
  if (_botDirectory.isEmpty) return;
  final out = <Map<String, dynamic>>[];
  for (final m in _botDirectory.values) {
    if (m['revoked'] == true || m['blocked'] == true) continue;
    final id = m['botId'] as String? ?? '';
    final handle = m['handle'] as String? ?? '';
    if (id.isEmpty || handle.isEmpty) continue;
    out.add({
      'botId': id,
      'handle': handle,
      'x25519Pub': m['x25519Pub'] ?? '',
      'displayName': m['displayName'] ?? handle,
      'description': m['description'] ?? '',
      'createdAt': m['createdAt'] ?? 0,
      'avatarUrl': m['avatarUrl'] ?? '',
      'bannerUrl': m['bannerUrl'] ?? '',
      'verified': m['verified'] == true,
      'blocked': m['blocked'] == true,
      'commands': _commandsForPublicRow(m),
    });
  }
  if (out.isEmpty) return;
  try {
    ws.sink.add(jsonEncode({
      'type': 'bot_dir_snapshot',
      'bots': out,
    }));
    stdout.writeln('[RLINK][Relay] bot_dir_snapshot → ${out.length} bots');
  } catch (e) {
    stdout.writeln('[RLINK][Relay] bot_dir_snapshot send: $e');
  }
}

void _broadcastBotDirSnapshotToAll() {
  for (final u in _users.values) {
    _sendBotDirSnapshot(u.ws);
  }
}

/// Публичные URL аватара/баннера бота (https или http, длина ≤ 2048).
bool _isAllowedBotMediaUrl(String url) {
  if (url.isEmpty) return true;
  if (url.length > 2048) return false;
  final u = Uri.tryParse(url);
  if (u == null || !u.hasScheme) return false;
  return u.scheme == 'https' || u.scheme == 'http';
}

bool _isBotBlockedOrRevoked(String botId) {
  final row = _botDirectory[botId];
  if (row == null) return false;
  return row['revoked'] == true || row['blocked'] == true;
}

String _botAdminCode(String botId) {
  final clean = botId.toLowerCase().replaceAll(RegExp(r'[^0-9a-f]'), '');
  if (clean.length < 12) return clean.toUpperCase();
  final s = clean.substring(0, 12).toUpperCase();
  return '${s.substring(0, 4)}-${s.substring(4, 8)}-${s.substring(8, 12)}';
}

String _normalizeBotAdminCode(String raw) {
  final clean = raw.trim().toLowerCase().replaceAll(RegExp(r'[^0-9a-f]'), '');
  return clean.length == 12 ? clean : '';
}

String? _resolveBotIdForAdmin(Map<String, dynamic> msg) {
  final botId = _jsonString(msg['botId']).toLowerCase().trim();
  if (RegExp(r'^[0-9a-f]{64}$').hasMatch(botId)) return botId;
  final code = _normalizeBotAdminCode(_jsonString(msg['botCode']));
  if (code.isEmpty) return null;
  String? found;
  for (final id in _botDirectory.keys) {
    if (!id.startsWith(code)) continue;
    if (found != null) return null;
    found = id;
  }
  return found;
}

bool _isKnownBot(String botId) => _botDirectory.containsKey(botId);

int _jsonIntField(Map<String, dynamic> row, String key) =>
    (row[key] as num?)?.toInt() ?? 0;

void _recordBotActivity(
  String botId,
  String type, {
  String peerId = '',
  int bytes = 0,
  String detail = '',
  bool persist = true,
}) {
  final id = botId.toLowerCase();
  final row = _botDirectory[id];
  if (row == null) return;
  final now = DateTime.now().millisecondsSinceEpoch;
  row['adminCode'] = _botAdminCode(id);
  row['lastSeenAt'] = now;
  row['lastActivityAt'] = now;
  switch (type) {
    case 'connect':
      row['lastConnectedAt'] = now;
      row['connectCount'] = _jsonIntField(row, 'connectCount') + 1;
      break;
    case 'disconnect':
      row['lastDisconnectedAt'] = now;
      break;
    case 'packet_in':
    case 'blob_in':
      row['messagesIn'] = _jsonIntField(row, 'messagesIn') + 1;
      break;
    case 'packet_out':
    case 'blob_out':
      row['messagesOut'] = _jsonIntField(row, 'messagesOut') + 1;
      break;
    case 'api_call':
      row['apiCalls'] = _jsonIntField(row, 'apiCalls') + 1;
      break;
  }
  final raw = row['activity'];
  final list = raw is List ? List<dynamic>.from(raw) : <dynamic>[];
  list.insert(0, {
    't': now,
    'type': type,
    if (peerId.isNotEmpty)
      'peer': peerId.substring(0, peerId.length.clamp(0, 12)),
    if (bytes > 0) 'bytes': bytes,
    if (detail.isNotEmpty)
      'detail': detail.length > 96 ? detail.substring(0, 96) : detail,
  });
  if (list.length > _botActivityMaxEvents) {
    list.removeRange(_botActivityMaxEvents, list.length);
  }
  row['activity'] = list;
  if (persist) _persistBotDirectory();
}

void _disconnectBotIfOnline(String botId, String reason) {
  final onlineBot = _users.remove(botId.toLowerCase());
  if (onlineBot == null) return;
  try {
    onlineBot.ws.sink.close(4003, reason);
  } catch (_) {}
  _broadcastPresence(botId.toLowerCase(), false);
}

String? _normalizeBotHandleQuery(String raw) {
  var s = raw.trim().toLowerCase();
  if (s.startsWith('@')) s = s.substring(1);
  s = s.replaceAll(RegExp(r'[^a-z0-9_]'), '');
  if (s.length < 2 || s.length > 32) return null;
  return s;
}

/// Публичный список команд из строки каталога (для snapshot / bot_info).
List<Map<String, dynamic>> _commandsForPublicRow(Map<String, dynamic> row) {
  final raw = row['commands'];
  final parsed = _parseBotCommandsInput(raw);
  return parsed ?? const <Map<String, dynamic>>[];
}

/// Возвращает `null`, если список невалиден.
List<Map<String, dynamic>>? _parseBotCommandsInput(dynamic raw) {
  if (raw == null) return const <Map<String, dynamic>>[];
  if (raw is! List) return null;
  if (raw.length > 32) return null;
  final out = <Map<String, dynamic>>[];
  for (final item in raw) {
    if (item is! Map) return null;
    final cmd = _jsonString(item['cmd']).trim();
    final desc = _jsonString(item['desc']).trim();
    if (cmd.isEmpty || cmd.length > 64) return null;
    if (!cmd.startsWith('/')) return null;
    if (!RegExp(r'^/[a-z0-9_]{1,63}$').hasMatch(cmd)) return null;
    if (desc.length > 256) return null;
    out.add({'cmd': cmd, 'desc': desc});
  }
  return out;
}

Map<String, dynamic>? _botRowByHandleNorm(String handleNorm) {
  for (final m in _botDirectory.values) {
    if (m['revoked'] == true || m['blocked'] == true) continue;
    final h = (m['handle'] as String?)?.toLowerCase() ?? '';
    if (h == handleNorm) return m;
  }
  return null;
}

void _handleBotInfoGet(_User user, Map<String, dynamic> msg) {
  final reqId = _jsonString(msg['reqId']).trim();
  void send(Map<String, dynamic> body) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_info_result',
        'reqId': reqId,
        ...body,
      }));
    } catch (_) {}
  }

  final hNorm = _normalizeBotHandleQuery(_jsonString(msg['handle']));
  if (hNorm == null) {
    send({
      'ok': false,
      'error': 'bad_handle',
      'handle': _jsonString(msg['handle'])
    });
    return;
  }
  final row = _botRowByHandleNorm(hNorm);
  if (row == null) {
    send({'ok': false, 'error': 'not_found', 'handle': hNorm});
    return;
  }
  final id = (row['botId'] as String?)?.toLowerCase() ?? '';
  if (id.length != 64) {
    send({'ok': false, 'error': 'not_found', 'handle': hNorm});
    return;
  }
  final handle = _jsonString(row['handle']);
  final dn = _jsonString(row['displayName']).trim();
  final desc = _jsonString(row['description']).trim();
  send({
    'ok': true,
    'handle': handle.isEmpty ? hNorm : handle,
    'displayName': dn.isEmpty ? handle : dn,
    'description': desc,
    'verified': row['verified'] == true,
    'botPublicKey': id,
    'avatarUrl': _jsonString(row['avatarUrl']).trim(),
    'bannerUrl': _jsonString(row['bannerUrl']).trim(),
    'commands': _commandsForPublicRow(row),
  });
}

void _handleBotCommandsSet(_User user, Map<String, dynamic> msg) {
  unawaited(_handleBotCommandsSetAsync(user, msg));
}

Future<void> _handleBotCommandsSetAsync(
  _User user,
  Map<String, dynamic> msg,
) async {
  void ack(bool ok, String err, String reqId) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_commands_set_ack',
        'ok': ok,
        if (!ok) 'error': err,
        'reqId': reqId,
      }));
    } catch (_) {}
  }

  final reqId = _jsonString(msg['reqId']).trim();
  final payloadJson = msg['payload'] as String?;
  final signatureHex = msg['signature'] as String?;

  if (payloadJson != null &&
      payloadJson.isNotEmpty &&
      payloadJson.length <= 16384 &&
      signatureHex != null &&
      signatureHex.length == 128) {
    Map<String, dynamic> obj;
    try {
      obj = jsonDecode(payloadJson) as Map<String, dynamic>;
    } catch (_) {
      ack(false, 'bad_json', '');
      return;
    }
    final rid = _jsonString(obj['reqId']).trim();
    if (rid.length > 64) {
      ack(false, 'bad_request', rid);
      return;
    }
    if (obj['v'] != 1) {
      ack(false, 'bad_version', rid);
      return;
    }
    final owner = _jsonString(obj['owner']).toLowerCase().trim();
    if (owner != user.publicKey || !RegExp(r'^[0-9a-f]{64}$').hasMatch(owner)) {
      ack(false, 'owner_mismatch', rid);
      return;
    }
    final botId = _jsonString(obj['botId']).toLowerCase().trim();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(botId)) {
      ack(false, 'bad_bot_id', rid);
      return;
    }
    final ts = (obj['ts'] as num?)?.toInt() ?? 0;
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if ((nowMs - ts).abs() > const Duration(minutes: 10).inMilliseconds) {
      ack(false, 'stale_ts', rid);
      return;
    }
    if (!obj.containsKey('commands')) {
      ack(false, 'missing_commands', rid);
      return;
    }
    if (!_checkBotOwnerPatchRate(owner)) {
      ack(false, 'rate_limited', rid);
      return;
    }
    final sigOk = await _verifyEd25519SignatureOnUtf8(
      payloadJson,
      signatureHex,
      owner,
    );
    if (!sigOk) {
      ack(false, 'bad_signature', rid);
      return;
    }
    final row = _botDirectory[botId];
    if (row == null || row['revoked'] == true) {
      ack(false, 'not_found', rid);
      return;
    }
    if ((row['ownerEd25519Pub'] as String?)?.toLowerCase() != owner) {
      ack(false, 'not_owner', rid);
      return;
    }
    final parsed = _parseBotCommandsInput(obj['commands']);
    if (parsed == null) {
      ack(false, 'bad_commands', rid);
      return;
    }
    row['commands'] = parsed;
    row['updatedAt'] = nowMs;
    _recordBotActivity(botId, 'commands_set',
        peerId: owner, detail: '${parsed.length} commands', persist: false);
    _persistBotDirectory();
    _broadcastBotDirSnapshotToAll();
    stdout.writeln(
        '[RLINK][Relay] bot_commands_set owner=$owner bot=$botId n=${parsed.length}');
    ack(true, '', rid);
    return;
  }

  final apiToken = msg['apiToken'] as String?;
  if (apiToken == null || apiToken.isEmpty) {
    ack(false, 'bad_request', reqId);
    return;
  }
  final tokenHash = _sha256HexUtf8(apiToken);
  String? botId;
  for (final e in _botDirectory.entries) {
    if (e.value['revoked'] == true) continue;
    if ((e.value['apiTokenHash'] as String?) == tokenHash) {
      botId = e.key;
      break;
    }
  }
  if (botId == null) {
    ack(false, 'bad_token', reqId);
    return;
  }
  if (user.publicKey != botId) {
    ack(false, 'wrong_connection', reqId);
    return;
  }
  if (!_checkBotOwnerPatchRate(botId)) {
    ack(false, 'rate_limited', reqId);
    return;
  }
  final parsed = _parseBotCommandsInput(msg['commands']);
  if (parsed == null) {
    ack(false, 'bad_commands', reqId);
    return;
  }
  final row = _botDirectory[botId];
  if (row == null || row['revoked'] == true) {
    ack(false, 'not_found', reqId);
    return;
  }
  row['commands'] = parsed;
  row['updatedAt'] = DateTime.now().millisecondsSinceEpoch;
  _recordBotActivity(botId, 'commands_set',
      detail: '${parsed.length} commands via apiToken', persist: false);
  _persistBotDirectory();
  _broadcastBotDirSnapshotToAll();
  stdout.writeln(
      '[RLINK][Relay] bot_commands_set apiToken bot=$botId n=${parsed.length}');
  ack(true, '', reqId);
}

String _jsonString(dynamic v) => v == null ? '' : v.toString();

bool _isAdminHashValid(String hash) {
  if (_relayAdminHash.isEmpty) return false;
  final h = hash.trim().toLowerCase();
  return h.isNotEmpty && h == _relayAdminHash;
}

bool _handleTakenByActiveBot(String handleLower) {
  for (final m in _botDirectory.values) {
    if (m['revoked'] == true) continue;
    if ((m['handle'] as String?)?.toLowerCase() == handleLower) return true;
  }
  return false;
}

void _handleBotRegisterStart(_User user, Map<String, dynamic> msg) {
  unawaited(_handleBotRegisterStartAsync(user, msg));
}

Future<void> _handleBotRegisterStartAsync(
  _User user,
  Map<String, dynamic> msg,
) async {
  void ackOk(Map<String, dynamic> extra) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_register_ack',
        'ok': true,
        ...extra,
      }));
    } catch (_) {}
  }

  void ackFail(String err) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_register_ack',
        'ok': false,
        'error': err,
      }));
    } catch (_) {}
  }

  final payloadJson = msg['payload'] as String?;
  final signatureHex = msg['signature'] as String?;
  if (payloadJson == null ||
      payloadJson.isEmpty ||
      payloadJson.length > 8192 ||
      signatureHex == null ||
      signatureHex.length != 128) {
    ackFail('bad_request');
    return;
  }

  Map<String, dynamic> obj;
  try {
    obj = jsonDecode(payloadJson) as Map<String, dynamic>;
  } catch (_) {
    ackFail('bad_json');
    return;
  }

  final v = obj['v'];
  if (v != 1) {
    ackFail('bad_version');
    return;
  }
  final owner = _jsonString(obj['owner']).toLowerCase().trim();
  final botPk = _jsonString(obj['botPublicKey']).toLowerCase().trim();
  final displayName = _jsonString(obj['displayName']).trim();
  final handleNorm = _normalizeBotHandle(_jsonString(obj['handle']));
  final ts = (obj['ts'] as num?)?.toInt() ?? 0;

  if (owner != user.publicKey) {
    ackFail('owner_mismatch');
    return;
  }
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(botPk) || botPk == owner) {
    ackFail('bad_bot_key');
    return;
  }
  if (handleNorm == null) {
    ackFail('bad_handle');
    return;
  }
  if (displayName.isEmpty || displayName.length > 64) {
    ackFail('bad_display_name');
    return;
  }
  final now = DateTime.now().millisecondsSinceEpoch;
  if ((now - ts).abs() > const Duration(minutes: 10).inMilliseconds) {
    ackFail('stale_ts');
    return;
  }

  if (!_checkBotRegisterStartRate(owner)) {
    ackFail('rate_limited');
    return;
  }

  final sigOk = await _verifyEd25519SignatureOnUtf8(
    payloadJson,
    signatureHex,
    owner,
  );
  if (!sigOk) {
    ackFail('bad_signature');
    return;
  }

  if (_handleTakenByActiveBot(handleNorm)) {
    ackFail('handle_taken');
    return;
  }
  if (_botDirectory.containsKey(botPk) &&
      _botDirectory[botPk]!['revoked'] != true) {
    ackFail('bot_key_registered');
    return;
  }

  _pruneExpiredBotClaims();
  for (final c in _botClaims.values) {
    if ((c['handle'] as String?)?.toLowerCase() == handleNorm) {
      ackFail('handle_pending');
      return;
    }
    if ((c['botPublicKey'] as String?)?.toLowerCase() == botPk) {
      ackFail('bot_key_pending');
      return;
    }
  }

  final claimId = _randomClaimId();
  final claimCode = _allocateUniqueBotClaimCode();
  if (claimCode == null) {
    ackFail('claim_code_alloc');
    return;
  }
  _botClaims[claimId] = {
    'owner': owner,
    'handle': handleNorm,
    'displayName': displayName,
    'description': _jsonString(obj['description']).trim(),
    'botPublicKey': botPk,
    'createdAt': now,
    'claimCode': claimCode,
  };
  _botClaimCodeToClaimId[claimCode.toUpperCase()] = claimId;

  stdout.writeln(
    '[RLINK][Relay] bot_register_start handle=@$handleNorm claim=$claimId code=$claimCode',
  );
  ackOk({
    'claimId': claimId,
    'claimCode': claimCode,
    'expiresInSec': _botClaimTtl.inSeconds,
    'handle': handleNorm,
    'botPublicKey': botPk,
  });
}

void _handleBotClaim(_User user, Map<String, dynamic> msg) {
  void ackOk(Map<String, dynamic> extra) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_claim_ack',
        'ok': true,
        ...extra,
      }));
    } catch (_) {}
  }

  void ackFail(String err) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_claim_ack',
        'ok': false,
        'error': err,
      }));
    } catch (_) {}
  }

  final rawClaim = (msg['claimId'] as String?)?.trim() ?? '';
  if (rawClaim.isEmpty) {
    ackFail('bad_claim');
    return;
  }

  _pruneExpiredBotClaims();

  late final String claimId;
  if (RegExp(r'^[0-9a-fA-F]{32}$').hasMatch(rawClaim)) {
    claimId = rawClaim.toLowerCase();
  } else {
    final canon = _normalizeBotClaimCodeInput(rawClaim);
    if (canon.isEmpty) {
      ackFail('bad_claim');
      return;
    }
    final id = _botClaimCodeToClaimId[canon];
    if (id == null || id.isEmpty) {
      ackFail('claim_not_found');
      return;
    }
    claimId = id;
  }

  final claim = _botClaims[claimId];
  if (claim == null) {
    ackFail('claim_not_found');
    return;
  }

  final botPk = (claim['botPublicKey'] as String?)?.toLowerCase() ?? '';
  if (botPk != user.publicKey) {
    ackFail('wrong_bot_connection');
    return;
  }
  if (user.x25519Key.isEmpty) {
    ackFail('missing_x25519');
    return;
  }

  final handleNorm = (claim['handle'] as String?)?.toLowerCase() ?? '';
  if (handleNorm.isEmpty) {
    ackFail('bad_claim_data');
    return;
  }

  if (_handleTakenByActiveBot(handleNorm)) {
    _removeBotClaim(claimId);
    ackFail('handle_taken');
    return;
  }

  final apiToken = _randomUrlToken();
  final tokenHash = _sha256HexUtf8(apiToken);

  _removeBotClaim(claimId);
  final nowMs = DateTime.now().millisecondsSinceEpoch;
  _botDirectory[botPk] = {
    'botId': botPk,
    'adminCode': _botAdminCode(botPk),
    'x25519Pub': user.x25519Key,
    'handle': handleNorm,
    'ownerEd25519Pub': claim['owner'],
    'displayName': claim['displayName'] ?? handleNorm,
    'description': claim['description'] ?? '',
    'createdAt': nowMs,
    'updatedAt': nowMs,
    'lastSeenAt': nowMs,
    'lastActivityAt': nowMs,
    'lastConnectedAt': nowMs,
    'lastDisconnectedAt': 0,
    'connectCount': 1,
    'messagesIn': 0,
    'messagesOut': 0,
    'apiCalls': 0,
    'revoked': false,
    'apiTokenHash': tokenHash,
    'webhookUrl': '',
    'avatarUrl': '',
    'bannerUrl': '',
    'verified': false,
    'blocked': false,
    'commands': <Map<String, dynamic>>[],
    'activity': <Map<String, dynamic>>[
      {
        't': nowMs,
        'type': 'claim',
        'detail': '@$handleNorm',
      }
    ],
  };
  _persistBotDirectory();

  stdout
      .writeln('[RLINK][Relay] bot_claim ok @$handleNorm bot=${user.shortId}');
  ackOk({
    'apiToken': apiToken,
    'handle': handleNorm,
    'botId': botPk,
    'displayName': claim['displayName'],
  });
}

void _handleBotOwnerList(_User user, Map<String, dynamic> msg) {
  unawaited(_handleBotOwnerListAsync(user, msg));
}

Future<void> _handleBotOwnerListAsync(
  _User user,
  Map<String, dynamic> msg,
) async {
  void ackFail(String err, String reqId) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_owner_list_ack',
        'ok': false,
        'error': err,
        'reqId': reqId,
      }));
    } catch (_) {}
  }

  void ackOk(List<Map<String, dynamic>> bots, String reqId) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_owner_list_ack',
        'ok': true,
        'bots': bots,
        'reqId': reqId,
      }));
    } catch (_) {}
  }

  final payloadJson = msg['payload'] as String?;
  final signatureHex = msg['signature'] as String?;
  if (payloadJson == null ||
      payloadJson.isEmpty ||
      payloadJson.length > 4096 ||
      signatureHex == null ||
      signatureHex.length != 128) {
    ackFail('bad_request', '');
    return;
  }

  Map<String, dynamic> obj;
  try {
    obj = jsonDecode(payloadJson) as Map<String, dynamic>;
  } catch (_) {
    ackFail('bad_json', '');
    return;
  }

  final reqId = _jsonString(obj['reqId']).trim();
  if (reqId.length > 64) {
    ackFail('bad_request', '');
    return;
  }

  if (obj['v'] != 1) {
    ackFail('bad_version', reqId);
    return;
  }

  final owner = _jsonString(obj['owner']).toLowerCase().trim();
  if (owner != user.publicKey) {
    ackFail('owner_mismatch', reqId);
    return;
  }
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(owner)) {
    ackFail('bad_request', reqId);
    return;
  }

  final ts = (obj['ts'] as num?)?.toInt() ?? 0;
  final nowMs = DateTime.now().millisecondsSinceEpoch;
  if ((nowMs - ts).abs() > const Duration(minutes: 10).inMilliseconds) {
    ackFail('stale_ts', reqId);
    return;
  }

  if (!_checkBotOwnerListRate(owner)) {
    ackFail('rate_limited', reqId);
    return;
  }

  final sigOk = await _verifyEd25519SignatureOnUtf8(
    payloadJson,
    signatureHex,
    owner,
  );
  if (!sigOk) {
    ackFail('bad_signature', reqId);
    return;
  }

  final bots = <Map<String, dynamic>>[];
  for (final m in _botDirectory.values) {
    if (m['revoked'] == true || m['blocked'] == true) continue;
    final op = (m['ownerEd25519Pub'] as String?)?.toLowerCase() ?? '';
    if (op != owner) continue;
    final id = m['botId'] as String? ?? '';
    final handle = m['handle'] as String? ?? '';
    if (id.isEmpty || handle.isEmpty) continue;
    bots.add({
      'botId': id,
      'handle': handle,
      'displayName': m['displayName'] ?? handle,
      'description': m['description'] ?? '',
      'avatarUrl': m['avatarUrl'] ?? '',
      'bannerUrl': m['bannerUrl'] ?? '',
      'verified': m['verified'] == true,
      'blocked': m['blocked'] == true,
      'lastSeenAt': m['lastSeenAt'] ?? 0,
      'messagesIn': m['messagesIn'] ?? 0,
      'messagesOut': m['messagesOut'] ?? 0,
    });
  }
  bots.sort((a, b) => (a['handle'] as String)
      .toLowerCase()
      .compareTo((b['handle'] as String).toLowerCase()));
  ackOk(bots, reqId);
}

void _handleBotOwnerPatch(_User user, Map<String, dynamic> msg) {
  unawaited(_handleBotOwnerPatchAsync(user, msg));
}

Future<void> _handleBotOwnerPatchAsync(
  _User user,
  Map<String, dynamic> msg,
) async {
  void ackFail(String err, String reqId) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_owner_patch_ack',
        'ok': false,
        'error': err,
        'reqId': reqId,
      }));
    } catch (_) {}
  }

  void ackOk(String reqId) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'bot_owner_patch_ack',
        'ok': true,
        'reqId': reqId,
      }));
    } catch (_) {}
  }

  final payloadJson = msg['payload'] as String?;
  final signatureHex = msg['signature'] as String?;
  if (payloadJson == null ||
      payloadJson.isEmpty ||
      payloadJson.length > 8192 ||
      signatureHex == null ||
      signatureHex.length != 128) {
    ackFail('bad_request', '');
    return;
  }

  Map<String, dynamic> obj;
  try {
    obj = jsonDecode(payloadJson) as Map<String, dynamic>;
  } catch (_) {
    ackFail('bad_json', '');
    return;
  }

  final reqId = _jsonString(obj['reqId']).trim();
  if (reqId.length > 64) {
    ackFail('bad_request', '');
    return;
  }

  if (obj['v'] != 1) {
    ackFail('bad_version', reqId);
    return;
  }

  final owner = _jsonString(obj['owner']).toLowerCase().trim();
  if (owner != user.publicKey) {
    ackFail('owner_mismatch', reqId);
    return;
  }
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(owner)) {
    ackFail('bad_request', reqId);
    return;
  }

  final botId = _jsonString(obj['botId']).toLowerCase().trim();
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(botId)) {
    ackFail('bad_bot_id', reqId);
    return;
  }

  final ts = (obj['ts'] as num?)?.toInt() ?? 0;
  final nowMs = DateTime.now().millisecondsSinceEpoch;
  if ((nowMs - ts).abs() > const Duration(minutes: 10).inMilliseconds) {
    ackFail('stale_ts', reqId);
    return;
  }

  final hasChange = obj.containsKey('displayName') ||
      obj.containsKey('description') ||
      obj.containsKey('avatarUrl') ||
      obj.containsKey('bannerUrl') ||
      obj['revoke'] == true ||
      obj['verifyRequest'] == true ||
      obj['clearAvatar'] == true ||
      obj['clearBanner'] == true;
  if (!hasChange) {
    ackFail('empty_patch', reqId);
    return;
  }

  if (!_checkBotOwnerPatchRate(owner)) {
    ackFail('rate_limited', reqId);
    return;
  }

  final sigOk = await _verifyEd25519SignatureOnUtf8(
    payloadJson,
    signatureHex,
    owner,
  );
  if (!sigOk) {
    ackFail('bad_signature', reqId);
    return;
  }

  final row = _botDirectory[botId];
  if (row == null || row['revoked'] == true) {
    ackFail('not_found', reqId);
    return;
  }
  if ((row['ownerEd25519Pub'] as String?)?.toLowerCase() != owner) {
    ackFail('not_owner', reqId);
    return;
  }

  if (obj['revoke'] == true) {
    row['revoked'] = true;
    row['updatedAt'] = nowMs;
    // Если бот онлайн — немедленно отключаем, чтобы он исчез из presence и поиска.
    _disconnectBotIfOnline(botId, 'bot_revoked');
    _recordBotActivity(botId, 'owner_revoke', peerId: owner, persist: false);
    _persistBotDirectory();
    _broadcastBotDirSnapshotToAll();
    stdout.writeln(
        '[RLINK][Relay] bot_owner_patch revoke bot=$botId owner=$owner');
    ackOk(reqId);
    return;
  }

  var changed = false;

  if (obj.containsKey('displayName')) {
    final n = _jsonString(obj['displayName']).trim();
    if (n.isEmpty || n.length > 64) {
      ackFail('bad_display_name', reqId);
      return;
    }
    row['displayName'] = n;
    changed = true;
  }
  if (obj.containsKey('description')) {
    final d = _jsonString(obj['description']).trim();
    if (d.length > 512) {
      ackFail('description_too_long', reqId);
      return;
    }
    row['description'] = d;
    changed = true;
  }

  if (obj['clearAvatar'] == true) {
    row['avatarUrl'] = '';
    changed = true;
  } else if (obj.containsKey('avatarUrl')) {
    final u = _jsonString(obj['avatarUrl']).trim();
    if (!_isAllowedBotMediaUrl(u)) {
      ackFail('bad_url', reqId);
      return;
    }
    row['avatarUrl'] = u;
    changed = true;
  }

  if (obj['clearBanner'] == true) {
    row['bannerUrl'] = '';
    changed = true;
  } else if (obj.containsKey('bannerUrl')) {
    final bu = _jsonString(obj['bannerUrl']).trim();
    if (!_isAllowedBotMediaUrl(bu)) {
      ackFail('bad_url', reqId);
      return;
    }
    row['bannerUrl'] = bu;
    changed = true;
  }

  // Заявка владельца на верификацию («галочку»). Фиксируем как флаг + запись
  // активности — админ видит её в панели и решает выдать галочку.
  if (obj['verifyRequest'] == true) {
    final note = _jsonString(obj['verifyNote']).trim();
    final trimmedNote = note.length > 200 ? note.substring(0, 200) : note;
    row['verifyRequested'] = true;
    row['verifyRequestedAt'] = nowMs;
    if (trimmedNote.isNotEmpty) row['verifyNote'] = trimmedNote;
    _recordBotActivity(botId, 'verify_request',
        peerId: owner, detail: trimmedNote, persist: false);
    changed = true;
  }

  if (changed) {
    row['updatedAt'] = nowMs;
    _recordBotActivity(botId, 'owner_patch', peerId: owner, persist: false);
    _persistBotDirectory();
    _broadcastBotDirSnapshotToAll();
    stdout.writeln('[RLINK][Relay] bot_owner_patch bot=$botId owner=$owner');
  }
  ackOk(reqId);
}

int _dirUpdatedAt(Map<String, dynamic> m) =>
    (m['updatedAt'] as num?)?.toInt() ?? 0;

void _sendChannelDirSnapshot(WebSocketChannel ws) {
  if (_channelDirectory.isEmpty) return;
  final entries = _channelDirectory.values.toList();
  entries.sort((a, b) => _dirUpdatedAt(b).compareTo(_dirUpdatedAt(a)));
  final slice = entries.length > _channelDirSnapshotMaxEntries
      ? entries.sublist(0, _channelDirSnapshotMaxEntries)
      : entries;
  try {
    ws.sink.add(jsonEncode({
      'type': 'channel_dir_snapshot',
      'channels': slice,
    }));
    stdout.writeln(
      '[RLINK][Relay] channel_dir_snapshot → ${slice.length} entries',
    );
  } catch (e) {
    stdout.writeln('[RLINK][Relay] channel_dir_snapshot send: $e');
  }
}

void _handleChannelDirPut(_User user, Map<String, dynamic> msg) {
  unawaited(_handleChannelDirPutAsync(user, msg));
}

void _broadcastChannelDirSnapshotToAll() {
  for (final u in _users.values) {
    _sendChannelDirSnapshot(u.ws);
  }
}

/// Relay-admin grants/clears a channel checkmark. Stored on the directory
/// record (created minimally if the channel hasn't published yet) so it is
/// server-authoritative and survives any re-login or admin re-publish.
void _handleAdminChannelVerify(_User user, Map<String, dynamic> msg) {
  final reqId = _jsonString(msg['reqId']);
  void ack(Map<String, dynamic> extra) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'admin_channel_verify_ack',
        if (reqId.isNotEmpty) 'reqId': reqId,
        ...extra,
      }));
    } catch (_) {}
  }

  if (!_isAdminHashValid(_jsonString(msg['adminHash']))) {
    ack({'ok': false, 'error': 'forbidden'});
    return;
  }
  final channelId = _jsonString(msg['channelId']);
  if (channelId.isEmpty) {
    ack({'ok': false, 'error': 'bad_channel_id'});
    return;
  }
  final verified = msg['verified'] == true;
  final verifiedBy = _jsonString(msg['verifiedBy']);

  final row = _channelDirectory[channelId] ??=
      <String, dynamic>{'channelId': channelId, 'isPublic': true};
  row['verified'] = verified;
  if (verified) {
    row['verifiedBy'] = verifiedBy.isEmpty ? 'admin' : verifiedBy;
  } else {
    row.remove('verifiedBy');
  }
  // Bump so clients (which rev-gate on updatedAt) re-apply the change.
  row['updatedAt'] = DateTime.now().millisecondsSinceEpoch;
  _persistChannelDirectory();
  _broadcastChannelDirSnapshotToAll();
  stdout.writeln(
      '[RLINK][Relay] admin_channel_verify $channelId verified=$verified');
  ack({'ok': true, 'channelId': channelId, 'verified': verified});
}

Future<void> _handleChannelDirPutAsync(
  _User user,
  Map<String, dynamic> msg,
) async {
  final payloadJson = msg['payload'] as String?;
  final signatureHex = msg['signature'] as String?;
  if (payloadJson == null ||
      payloadJson.isEmpty ||
      payloadJson.length > _channelDirMaxPayloadChars) {
    return;
  }
  if (signatureHex == null || signatureHex.length != 128) return;

  Map<String, dynamic> obj;
  try {
    obj = jsonDecode(payloadJson) as Map<String, dynamic>;
  } catch (_) {
    return;
  }

  final channelId = obj['channelId'] as String?;
  final adminId = obj['adminId'] as String?;
  if (channelId == null ||
      channelId.isEmpty ||
      adminId == null ||
      adminId.isEmpty) {
    return;
  }
  if (adminId != user.publicKey) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'channel_dir_ack',
        'ok': false,
        'error': 'admin_mismatch',
      }));
    } catch (_) {}
    return;
  }

  if (!_checkChannelDirPutRate(adminId)) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'channel_dir_ack',
        'ok': false,
        'error': 'rate_limited',
      }));
    } catch (_) {}
    return;
  }

  final ok =
      await _verifyChannelDirSignature(payloadJson, signatureHex, adminId);
  if (!ok) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'channel_dir_ack',
        'ok': false,
        'error': 'bad_signature',
      }));
    } catch (_) {}
    return;
  }

  final updatedAt = _dirUpdatedAt(obj);
  if (updatedAt <= 0) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'channel_dir_ack',
        'ok': false,
        'error': 'bad_updatedAt',
      }));
    } catch (_) {}
    return;
  }

  final tomb = _channelDirTombstones[channelId] ?? 0;
  if (updatedAt <= tomb) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'channel_dir_ack',
        'ok': false,
        'error': 'stale',
      }));
    } catch (_) {}
    return;
  }

  final isPublic = obj['isPublic'] as bool? ?? true;
  if (!isPublic) {
    _channelDirectory.remove(channelId);
    if (updatedAt > tomb) {
      _channelDirTombstones[channelId] = updatedAt;
    }
    _persistChannelDirectory();
    stdout.writeln(
      '[RLINK][Relay] channel_dir remove $channelId (tombstone $updatedAt)',
    );
    try {
      user.ws.sink.add(jsonEncode({'type': 'channel_dir_ack', 'ok': true}));
    } catch (_) {}
    return;
  }

  final existing = _channelDirectory[channelId];
  if (existing != null) {
    if (updatedAt < _dirUpdatedAt(existing)) {
      try {
        user.ws.sink.add(jsonEncode({
          'type': 'channel_dir_ack',
          'ok': false,
          'error': 'stale',
        }));
      } catch (_) {}
      return;
    }
  }

  // Verification is relay-authoritative: only admin_channel_verify grants or
  // clears it. A normal directory put by the channel admin can neither
  // self-verify nor wipe a platform-granted checkmark — carry it over.
  if (existing != null && existing['verified'] == true) {
    obj['verified'] = true;
    obj['verifiedBy'] = existing['verifiedBy'];
  } else {
    obj['verified'] = false;
    obj.remove('verifiedBy');
  }

  _channelDirectory[channelId] = obj;
  _persistChannelDirectory();
  stdout.writeln(
    '[RLINK][Relay] channel_dir put $channelId updatedAt=$updatedAt',
  );
  try {
    user.ws.sink.add(jsonEncode({'type': 'channel_dir_ack', 'ok': true}));
  } catch (_) {}
}

void _loadAccountBlobs() {
  try {
    final f = File('account_blobs.json');
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    decoded.forEach((k, v) {
      if (k is String && v is String) _accountBlobs[k] = v;
    });
    stdout.writeln(
        '[RLINK][Relay] Loaded ${_accountBlobs.length} account sync blobs');
  } catch (e) {
    stdout.writeln('[RLINK][Relay] account_blobs load: $e');
  }
}

bool get _webPushConfigured =>
    _vapidPublicKey.isNotEmpty && _vapidPrivateKeyPem.isNotEmpty;

void _loadPushSubscriptions() {
  try {
    final f = File(_pushSubsFile);
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    decoded.forEach((k, v) {
      if (k is! String || v is! List) return;
      final list = <Map<String, dynamic>>[];
      for (final item in v) {
        if (item is Map) {
          list.add(Map<String, dynamic>.from(item));
        }
      }
      if (list.isNotEmpty) {
        _pushSubscriptions[k.toLowerCase()] = list;
      }
    });
    stdout.writeln(
      '[RLINK][Relay] Loaded push subscriptions for ${_pushSubscriptions.length} recipients',
    );
  } catch (e) {
    stdout.writeln('[RLINK][Relay] push_subscriptions load: $e');
  }
}

void _persistPushSubscriptions() {
  try {
    File(_pushSubsFile).writeAsStringSync(jsonEncode(_pushSubscriptions));
  } catch (e) {
    stdout.writeln('[RLINK][Relay] push_subscriptions save: $e');
  }
}

void _loadMailbox() {
  try {
    final f = File(_mailboxFile);
    if (!f.existsSync()) return;
    final decoded = jsonDecode(f.readAsStringSync());
    if (decoded is! Map) return;
    decoded.forEach((recipient, value) {
      if (recipient is! String || value is! Map) return;
      final byId = <String, Map<String, dynamic>>{};
      value.forEach((msgId, envelope) {
        if (msgId is String && envelope is Map) {
          byId[msgId] = Map<String, dynamic>.from(envelope);
        }
      });
      if (byId.isNotEmpty) _mailbox[recipient.toLowerCase()] = byId;
    });
    stdout.writeln(
        '[RLINK][Relay] Loaded mailbox for ${_mailbox.length} recipients');
  } catch (e) {
    stdout.writeln('[RLINK][Relay] mailbox load: $e');
  }
}

void _persistMailbox() {
  _mailboxPersistTimer?.cancel();
  _mailboxPersistTimer = Timer(const Duration(seconds: 2), () async {
    try {
      await File(_mailboxFile).writeAsString(jsonEncode(_mailbox));
    } catch (e) {
      stdout.writeln('[RLINK][Relay] mailbox save: $e');
    }
  });
}

void _queueForRecipient(
  String recipientKey,
  String relayMsgId,
  Map<String, dynamic> envelope,
) {
  final key = recipientKey.toLowerCase();
  final bucket =
      _mailbox.putIfAbsent(key, () => <String, Map<String, dynamic>>{});
  bucket[relayMsgId] = envelope;
  while (bucket.length > _mailboxMaxPerRecipient) {
    bucket.remove(bucket.keys.first);
  }
  _persistMailbox();
}

void _ackRecipientMessage(String recipientKey, String relayMsgId) {
  final bucket = _mailbox[recipientKey.toLowerCase()];
  if (bucket == null) return;
  bucket.remove(relayMsgId);
  if (bucket.isEmpty) _mailbox.remove(recipientKey.toLowerCase());
  _persistMailbox();
}

void _sendMailboxSnapshot(_User user) {
  final bucket = _mailbox[user.publicKey];
  if (bucket == null || bucket.isEmpty) return;
  var sent = 0;
  for (final env in bucket.values) {
    try {
      user.ws.sink.add(jsonEncode(env));
      sent++;
    } catch (_) {}
  }
  stdout.writeln(
      '[RLINK][Relay] mailbox replay → ${user.shortId}: $sent queued packets');
}

String _vapidAuthHeader(String endpoint) {
  final uri = Uri.parse(endpoint);
  final aud = '${uri.scheme}://${uri.host}';
  final jwt = JWT({'aud': aud, 'sub': _vapidSubject}).sign(
    ECPrivateKey(_vapidPrivateKeyPem),
    algorithm: JWTAlgorithm.ES256,
    expiresIn: const Duration(hours: 12),
  );
  return 'vapid t=$jwt, k=$_vapidPublicKey';
}

Future<void> _notifyRecipientQueued({
  required String recipientKey,
  required String senderKey,
  String kind = 'message',
}) async {
  if (!_webPushConfigured) return;
  final now = DateTime.now();
  final prev = _lastPushForRecipient[recipientKey];
  if (prev != null && now.difference(prev).inSeconds < _pushCooldownSeconds) {
    return;
  }
  final subs = _pushSubscriptions[recipientKey];
  if (subs == null || subs.isEmpty) return;
  final payload = utf8.encode(jsonEncode({
    'title': 'Rlink',
    'body': kind == 'call' ? 'Входящий звонок' : 'Новое сообщение',
    'tag': 'rlink-${senderKey.substring(0, senderKey.length.clamp(0, 8))}',
    'data': {'recipient': recipientKey, 'kind': kind},
  }));
  final toRemoveEndpoints = <String>{};
  final client = HttpClient();
  try {
    for (final sub in subs) {
      final endpoint = (sub['endpoint'] as String?)?.trim() ?? '';
      if (endpoint.isEmpty) continue;
      try {
        final req = await client.postUrl(Uri.parse(endpoint));
        req.headers.set('TTL', '60');
        req.headers.set('Authorization', _vapidAuthHeader(endpoint));
        req.headers.set('Urgency', 'high');
        req.headers.set('Content-Type', 'application/json');
        req.add(payload);
        final resp = await req.close();
        if (resp.statusCode == 404 || resp.statusCode == 410) {
          toRemoveEndpoints.add(endpoint);
        }
      } catch (_) {}
    }
  } finally {
    client.close(force: true);
  }
  if (toRemoveEndpoints.isNotEmpty) {
    subs.removeWhere(
      (s) => toRemoveEndpoints.contains((s['endpoint'] as String?) ?? ''),
    );
    if (subs.isEmpty) _pushSubscriptions.remove(recipientKey);
    _persistPushSubscriptions();
  }
  _lastPushForRecipient[recipientKey] = now;
}

String _queuedKindFromPacketData(String dataB64) {
  try {
    final decoded = utf8.decode(base64Decode(dataB64));
    final obj = jsonDecode(decoded);
    if (obj is! Map) return 'message';
    if (obj['t'] != 'call_sig' && obj['type'] != 'call_sig') return 'message';
    final payload = obj['p'] ?? obj['payload'];
    if (payload is Map && payload['st'] == 'invite') return 'call';
  } catch (_) {}
  return 'message';
}

void _upsertPushSubscription(String recipientKey, Map<String, dynamic> sub) {
  final key = recipientKey.toLowerCase();
  final endpoint = (sub['endpoint'] as String?)?.trim() ?? '';
  if (endpoint.isEmpty) return;
  final list = _pushSubscriptions.putIfAbsent(
    key,
    () => <Map<String, dynamic>>[],
  );
  list.removeWhere((s) => (s['endpoint'] as String?) == endpoint);
  list.add(sub);
  while (list.length > 8) {
    list.removeAt(0);
  }
  _persistPushSubscriptions();
}

String _normalizeB64Url(String value) {
  final v = value.trim();
  if (v.isEmpty) return '';
  var normalized = v.replaceAll('-', '+').replaceAll('_', '/');
  while (normalized.length % 4 != 0) {
    normalized += '=';
  }
  return base64Url.encode(base64Decode(normalized)).replaceAll('=', '');
}

void _persistAccountBlobs() {
  try {
    File('account_blobs.json').writeAsStringSync(jsonEncode(_accountBlobs));
  } catch (e) {
    stdout.writeln('[RLINK][Relay] account_blobs save: $e');
  }
}

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
  // 50 MB per-message hard limit. Client already chunks large files into
  // ~90 KB pieces automatically, so this backstop is rarely reached.
  if (raw.length > 50 * 1024 * 1024) return;

  Map<String, dynamic> msg;
  try {
    msg = jsonDecode(raw) as Map<String, dynamic>;
  } catch (_) {
    return;
  }

  final type = msg['type'] as String?;
  if (type == null) return;

  if (_isBotBlockedOrRevoked(user.publicKey) && type != 'ping') {
    try {
      user.ws.sink
          .add(jsonEncode({'type': 'error', 'msg': 'bot_access_denied'}));
    } catch (_) {}
    return;
  }

  // Blobs и каталог каналов / боты не считаем в общий flood лимит.
  if (type != 'blob' &&
      type != 'channel_dir_put' &&
      type != 'bot_register_start' &&
      type != 'bot_claim' &&
      type != 'bot_owner_list' &&
      type != 'bot_owner_patch' &&
      type != 'bot_info_get' &&
      type != 'bot_commands_set' &&
      type != 'admin_password_update') {
    if (!_checkRate(user.publicKey)) {
      user.ws.sink.add(jsonEncode({'type': 'error', 'msg': 'rate_limited'}));
      return;
    }
  }

  switch (type) {
    case 'packet':
      _handlePacket(user, msg);
      break;
    case 'broadcast':
      _handleBroadcast(user, msg);
      break;
    case 'blob':
      _handleBlob(user, msg);
      break;
    case 'search':
      _handleSearch(user, msg);
      break;
    case 'ping':
      user.ws.sink.add(jsonEncode({'type': 'pong'}));
      break;
    case 'account_sync_put':
      _handleAccountSyncPut(user, msg);
      break;
    case 'channel_dir_put':
      _handleChannelDirPut(user, msg);
      break;
    case 'bot_register_start':
      _handleBotRegisterStart(user, msg);
      break;
    case 'bot_claim':
      _handleBotClaim(user, msg);
      break;
    case 'bot_owner_list':
      _handleBotOwnerList(user, msg);
      break;
    case 'bot_owner_patch':
      _handleBotOwnerPatch(user, msg);
      break;
    case 'bot_info_get':
      _handleBotInfoGet(user, msg);
      break;
    case 'bot_commands_set':
      _handleBotCommandsSet(user, msg);
      break;
    case 'admin_bot_list':
      _handleAdminBotList(user, msg);
      break;
    case 'admin_bot_update':
      _handleAdminBotUpdate(user, msg);
      break;
    case 'admin_channel_verify':
      _handleAdminChannelVerify(user, msg);
      break;
    case 'admin_password_update':
      _handleAdminPasswordUpdate(user, msg);
      break;
    case 'relay_ack':
      _handleRelayAck(user, msg);
      break;
    case 'presence':
      // Client signals away (backgrounded) or back (resumed).
      // We broadcast online=false/true so peers see correct status without
      // waiting for the WebSocket to actually close (which may not happen while
      // a foreground service keeps the socket alive on Android).
      final reqAway = msg['away'] as bool? ?? false;
      if (user.away != reqAway) {
        user.away = reqAway;
        _broadcastPresence(user.publicKey, !reqAway);
      }
      break;
  }
}

void _handleAdminPasswordUpdate(_User user, Map<String, dynamic> msg) {
  final reqId = _jsonString(msg['reqId']).trim();
  void ack(Map<String, dynamic> body) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'admin_password_update_ack',
        'reqId': reqId,
        ...body,
      }));
    } catch (_) {}
  }

  final oldHash = _jsonString(msg['oldHash']).toLowerCase().trim();
  final newHash = _jsonString(msg['newHash']).toLowerCase().trim();
  if (!_isSha256Hex(oldHash) || !_isSha256Hex(newHash)) {
    ack({'ok': false, 'error': 'bad_hash'});
    return;
  }
  if (_relayAdminHash.isEmpty) {
    ack({'ok': false, 'error': 'admin_not_configured'});
    return;
  }
  if (!_isAdminHashValid(oldHash)) {
    ack({'ok': false, 'error': 'forbidden'});
    return;
  }
  _relayAdminHash = newHash;
  _persistRelayAdminConfig();
  stdout.writeln('[RLINK][Relay] admin hash updated by ${user.shortId}');
  ack({'ok': true});
}

void _handleRelayAck(_User user, Map<String, dynamic> msg) {
  final relayMsgId = msg['msgId'] as String?;
  if (relayMsgId == null || relayMsgId.isEmpty) return;
  _ackRecipientMessage(user.publicKey, relayMsgId);
}

void _handleAdminBotList(_User user, Map<String, dynamic> msg) {
  final reqId = _jsonString(msg['reqId']).trim();
  void ack(Map<String, dynamic> body) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'admin_bot_list_ack',
        'reqId': reqId,
        ...body,
      }));
    } catch (_) {}
  }

  final adminHash = _jsonString(msg['adminHash']);
  if (!_isAdminHashValid(adminHash)) {
    ack({'ok': false, 'error': 'forbidden'});
    return;
  }
  final includeRevoked = msg['includeRevoked'] == true;
  final query = _jsonString(msg['q']).trim().toLowerCase();
  final out = <Map<String, dynamic>>[];
  for (final m in _botDirectory.values) {
    final revoked = m['revoked'] == true;
    if (revoked && !includeRevoked) continue;
    final id = _jsonString(m['botId']);
    final adminCode = _jsonString(m['adminCode']).isEmpty
        ? _botAdminCode(id)
        : _jsonString(m['adminCode']);
    final handle = _jsonString(m['handle']);
    final displayName = _jsonString(m['displayName']).isEmpty
        ? handle
        : _jsonString(m['displayName']);
    final owner = _jsonString(m['ownerEd25519Pub']);
    final blocked = m['blocked'] == true;
    final verified = m['verified'] == true;
    final online = _users.containsKey(id.toLowerCase());
    if (query.isNotEmpty) {
      final hay =
          '$id $adminCode $handle $displayName $owner ${_jsonString(m['description'])}'
              .toLowerCase();
      if (!hay.contains(query)) continue;
    }
    final activityRaw = m['activity'];
    final activity = activityRaw is List
        ? activityRaw
            .whereType<Map>()
            .take(12)
            .map((e) => Map<String, dynamic>.from(e))
            .toList()
        : <Map<String, dynamic>>[];
    out.add({
      'botId': id,
      'adminCode': adminCode,
      'handle': handle,
      'displayName': displayName,
      'description': _jsonString(m['description']),
      'ownerEd25519Pub': owner,
      'createdAt': m['createdAt'] ?? 0,
      'updatedAt': m['updatedAt'] ?? 0,
      'lastSeenAt': m['lastSeenAt'] ?? 0,
      'lastActivityAt': m['lastActivityAt'] ?? 0,
      'lastConnectedAt': m['lastConnectedAt'] ?? 0,
      'lastDisconnectedAt': m['lastDisconnectedAt'] ?? 0,
      'connectCount': m['connectCount'] ?? 0,
      'messagesIn': m['messagesIn'] ?? 0,
      'messagesOut': m['messagesOut'] ?? 0,
      'apiCalls': m['apiCalls'] ?? 0,
      'online': online,
      'blocked': blocked,
      'verified': verified,
      'revoked': revoked,
      'verifyRequested': m['verifyRequested'] == true,
      'verifyRequestedAt': m['verifyRequestedAt'] ?? 0,
      'verifyNote': _jsonString(m['verifyNote']),
      'activity': activity,
    });
  }
  out.sort((a, b) => ((b['lastActivityAt'] as num?)?.toInt() ?? 0)
      .compareTo((a['lastActivityAt'] as num?)?.toInt() ?? 0));
  ack({'ok': true, 'bots': out});
}

void _handleAdminBotUpdate(_User user, Map<String, dynamic> msg) {
  final reqId = _jsonString(msg['reqId']).trim();
  void ack(Map<String, dynamic> body) {
    try {
      user.ws.sink.add(jsonEncode({
        'type': 'admin_bot_update_ack',
        'reqId': reqId,
        ...body,
      }));
    } catch (_) {}
  }

  final adminHash = _jsonString(msg['adminHash']);
  if (!_isAdminHashValid(adminHash)) {
    ack({'ok': false, 'error': 'forbidden'});
    return;
  }
  final botId = _resolveBotIdForAdmin(msg);
  if (botId == null) {
    ack({'ok': false, 'error': 'bad_bot_id'});
    return;
  }
  final row = _botDirectory[botId];
  if (row == null) {
    ack({'ok': false, 'error': 'not_found'});
    return;
  }
  var changed = false;
  if (msg.containsKey('verified')) {
    row['verified'] = msg['verified'] == true;
    // Выдача/снятие галочки закрывает заявку владельца.
    if (row.containsKey('verifyRequested')) row['verifyRequested'] = false;
    changed = true;
  }
  if (msg.containsKey('blocked')) {
    row['blocked'] = msg['blocked'] == true;
    if (row['blocked'] == true) {
      _disconnectBotIfOnline(botId, 'bot_blocked');
    }
    changed = true;
  }
  if (msg['revoke'] == true) {
    row['revoked'] = true;
    row['blocked'] = true;
    _disconnectBotIfOnline(botId, 'bot_revoked');
    changed = true;
  }
  if (!changed) {
    ack({'ok': false, 'error': 'empty_patch'});
    return;
  }
  row['updatedAt'] = DateTime.now().millisecondsSinceEpoch;
  _recordBotActivity(botId, 'admin_update',
      detail:
          'verified=${row['verified'] == true} blocked=${row['blocked'] == true} revoked=${row['revoked'] == true}',
      persist: false);
  _persistBotDirectory();
  _broadcastBotDirSnapshotToAll();
  ack({'ok': true});
}

/// Клиент кладёт зашифрованный JSON (n/ct/m от ChaCha20), тот же формат что admin_cfg2.
void _handleAccountSyncPut(_User user, Map<String, dynamic> msg) {
  final data = msg['data'] as String?;
  if (data == null || data.isEmpty || data.length > 131072) return;
  _accountBlobs[user.publicKey] = data;
  _persistAccountBlobs();
  try {
    user.ws.sink.add(jsonEncode({'type': 'account_sync_ack', 'ok': true}));
  } catch (_) {}
  print(
      '[RLINK][Relay] account_sync_put ${user.shortId} (${data.length} chars)');
}

void _handlePacket(_User sender, Map<String, dynamic> msg) {
  final toRaw = msg['to'] as String?;
  final data = msg['data'] as String?; // base64-encoded encrypted packet
  if (toRaw == null || data == null) return;
  final noPush = msg['noPush'] as bool? ?? false;
  if (data.length > 262144) {
    _droppedOversizePackets++;
    return; // 256 KB max (blob chunks double-base64 ~90 KB each)
  }
  final to = toRaw.toLowerCase();
  final relayMsgId = (msg['msgId'] as String?) ??
      'pkt_${DateTime.now().microsecondsSinceEpoch}';
  final senderIsBot = _isKnownBot(sender.publicKey);
  final recipientIsBot = _isKnownBot(to);
  if (senderIsBot) {
    _recordBotActivity(sender.publicKey, 'packet_out',
        peerId: to, bytes: data.length);
  }

  final envelope = <String, dynamic>{
    'type': 'packet',
    'from': sender.publicKey,
    'data': data,
    'relayMsgId': relayMsgId,
  };
  _queueForRecipient(to, relayMsgId, envelope);

  final recipient = _users[to];
  if (recipient == null) {
    if (!noPush) {
      final kind = _queuedKindFromPacketData(data);
      unawaited(_notifyRecipientQueued(
        recipientKey: to,
        senderKey: sender.publicKey,
        kind: kind,
      ));
    }
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': to,
      'status': 'queued_offline',
    }));
    if (recipientIsBot) {
      // Гибридная модель: бот работает на ПК/сервере владельца. Сообщение
      // поставлено в очередь и будет доставлено, когда процесс подключится, а
      // отправителю показываем локальную заглушку «Бот не в сети…».
      sender.ws.sink.add(jsonEncode({
        'type': 'bot_offline',
        'bot': to,
        'relayMsgId': relayMsgId,
      }));
    }
    return;
  }
  try {
    if (recipientIsBot) {
      _recordBotActivity(to, 'packet_in',
          peerId: sender.publicKey, bytes: data.length);
    }
    recipient.ws.sink.add(jsonEncode(envelope));
    _forwardedPackets++;
    if (_verbosePacketLogs) {
      stdout.writeln(
          '[RLINK][Relay] Packet: ${sender.shortId} → ${recipient.shortId} (${data.length} chars)');
    }
  } catch (e) {
    stdout.writeln('[RLINK][Relay] Packet forward failed: $e');
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': to,
      'status': 'error',
    }));
  }
}

void _handleBroadcast(_User sender, Map<String, dynamic> msg) {
  final data = msg['data'] as String?;
  if (data == null) return;
  if (data.length > 262144) {
    _droppedOversizePackets++;
    return;
  }

  final encoded = jsonEncode({
    'type': 'packet',
    'from': sender.publicKey,
    'data': data,
  });

  // Forward to ALL online users except sender
  var sent = 0;
  for (final user in _users.values) {
    if (user.publicKey == sender.publicKey) continue;
    try {
      user.ws.sink.add(encoded);
      sent++;
    } catch (_) {}
  }
  _forwardedBroadcastPackets += sent;
  if (_verbosePacketLogs) {
    stdout.writeln(
        '[RLINK][Relay] Broadcast from ${sender.shortId}: ${data.length} chars → $sent peers');
  }
}

void _handleBlob(_User sender, Map<String, dynamic> msg) {
  final toRaw = msg['to'] as String?;
  if (toRaw == null) return;
  final noPush = msg['noPush'] as bool? ?? false;
  final to = toRaw.toLowerCase();
  final fullTo = (msg['fullTo'] as String?)?.toLowerCase();
  // Use fullTo (full public key) for routing when available;
  // fall back to 'to' (may be short key from older clients).
  final routeKey = (fullTo != null && fullTo.length == 64) ? fullTo : to;
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(routeKey)) {
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': routeKey,
      'status': 'error',
    }));
    return;
  }
  final relayMsgId = msg['msgId'] as String?;
  if (relayMsgId == null || relayMsgId.isEmpty) return;
  final data = msg['data'] as String?;
  if (data == null || data.isEmpty) return;
  if (data.length > 209715200) {
    // 200 MB max for a single blob message (base64). Raised from 10 MB.
    // Large files are already chunked client-side (48 KB pieces), so this
    // per-message cap is rarely the binding constraint.
    return;
  }
  final senderIsBot = _isKnownBot(sender.publicKey);
  final recipientIsBot = _isKnownBot(routeKey);
  if (senderIsBot) {
    _recordBotActivity(sender.publicKey, 'blob_out',
        peerId: routeKey, bytes: data.length);
  }

  // Forward the entire blob as-is, replacing 'to' with 'from'
  final forwarded = Map<String, dynamic>.from(msg);
  forwarded.remove('to');
  forwarded['from'] = sender.publicKey;
  forwarded['type'] = 'blob';
  forwarded['relayMsgId'] = relayMsgId;
  _queueForRecipient(routeKey, relayMsgId, forwarded);

  final recipient = _users[routeKey];
  if (recipient == null) {
    if (!noPush) {
      unawaited(_notifyRecipientQueued(
        recipientKey: routeKey,
        senderKey: sender.publicKey,
      ));
    }
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': routeKey,
      'status': 'queued_offline',
    }));
    return;
  }

  try {
    if (recipientIsBot) {
      _recordBotActivity(routeKey, 'blob_in',
          peerId: sender.publicKey, bytes: data.length);
    }
    recipient.ws.sink.add(jsonEncode(forwarded));
    _forwardedBlobs++;
    final dataLen = (msg['data'] as String?)?.length ?? 0;
    if (_verbosePacketLogs) {
      stdout.writeln(
          '[RLINK][Relay] Blob forwarded: ${sender.publicKey.substring(0, 8)} → ${routeKey.substring(0, 8)} ($dataLen chars)');
    }
  } catch (e) {
    stdout.writeln('[RLINK][Relay] Blob forward failed: $e');
    sender.ws.sink.add(jsonEncode({
      'type': 'delivery_status',
      'to': routeKey,
      'status': 'error',
    }));
  }
}

void _handleSearch(_User requester, Map<String, dynamic> msg) {
  final query = (msg['query'] as String?)?.toLowerCase().trim();
  if (query == null || query.isEmpty) return;

  final results = <Map<String, dynamic>>[];
  final seenKeys = <String>{};

  final qBare = query.startsWith('@') ? query.substring(1) : query;

  for (final m in _botDirectory.values) {
    if (m['revoked'] == true) continue;
    final botId = (m['botId'] as String?) ?? '';
    final handle = (m['handle'] as String?)?.toLowerCase() ?? '';
    if (botId.isEmpty || handle.isEmpty) continue;
    final nickAt = '@$handle';
    final match = handle.contains(qBare) ||
        nickAt.contains(query) ||
        botId.toLowerCase().startsWith(query);
    if (!match) continue;
    final online = _users.containsKey(botId);
    final u = _users[botId];
    final x25519 = (u?.x25519Key.isNotEmpty ?? false)
        ? u!.x25519Key
        : (m['x25519Pub'] as String? ?? '');
    final av = (m['avatarUrl'] as String?)?.trim() ?? '';
    final bn = (m['bannerUrl'] as String?)?.trim() ?? '';
    results.add({
      'publicKey': botId,
      'nick': nickAt,
      'shortId': botId.substring(0, 8),
      'online': online,
      if (x25519.isNotEmpty) 'x25519': x25519,
      'isBot': true,
      if (av.isNotEmpty) 'avatarUrl': av,
      if (bn.isNotEmpty) 'bannerUrl': bn,
    });
    seenKeys.add(botId);
    if (results.length >= 20) break;
  }

  for (final user in _users.values) {
    if (results.length >= 20) break;
    if (user.publicKey == requester.publicKey) continue;
    if (_isBotBlockedOrRevoked(user.publicKey)) continue;
    if (seenKeys.contains(user.publicKey)) continue;
    final nickLower = user.nick.toLowerCase();
    final shortLower = user.shortId.toLowerCase();
    if (nickLower.contains(query) ||
        shortLower.contains(query) ||
        user.publicKey.toLowerCase().startsWith(query)) {
      results.add({
        'publicKey': user.publicKey,
        'nick': user.nick,
        'shortId': user.shortId,
        'online': !user.away,
        if (user.x25519Key.isNotEmpty) 'x25519': user.x25519Key,
      });
      seenKeys.add(user.publicKey);
    }
  }

  requester.ws.sink.add(jsonEncode({
    'type': 'search_result',
    'results': results,
  }));
  print(
      '[RLINK][Relay] Search "$query" by ${requester.publicKey.substring(0, 8)}: ${results.length} results');
}

// ── WebSocket handler ───────────────────────────────────────────

shelf.Handler _wsHandler() {
  // pingInterval=25s включает native WebSocket control-pings (RFC 6455 ping/pong
  // на уровне протокола, не application-level). Браузер отвечает автоматически
  // без JS-таймеров — не подвержен throttling неактивных табов. Это держит WS
  // живым через tuna и другие прокси (обычный idle-timeout 60-120 сек).
  return webSocketHandler((WebSocketChannel ws) {
    _User? user;
    ws.stream.listen(
      (raw) {
        if (user == null) {
          // First message must be registration
          if (raw is! String) return;
          try {
            final msg = jsonDecode(raw) as Map<String, dynamic>;
            if (msg['type'] != 'register') {
              ws.sink
                  .add(jsonEncode({'type': 'error', 'msg': 'register_first'}));
              return;
            }
            final publicKeyRaw = msg['publicKey'] as String?;
            final nick = msg['nick'] as String? ?? '';
            final x25519Key = msg['x25519'] as String? ?? '';
            if (publicKeyRaw == null ||
                !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(publicKeyRaw)) {
              ws.sink.add(jsonEncode({'type': 'error', 'msg': 'invalid_key'}));
              return;
            }
            final publicKey = publicKeyRaw.toLowerCase();

            // Disconnect previous connection for same key
            final prev = _users[publicKey];
            if (prev != null) {
              try {
                prev.ws.sink.close(4001, 'replaced_by_new_connection');
              } catch (_) {}
            }

            user = _User(
                ws: ws, publicKey: publicKey, nick: nick, x25519Key: x25519Key);
            _users[publicKey] = user!;
            if (_isBotBlockedOrRevoked(publicKey)) {
              try {
                ws.sink.add(jsonEncode({
                  'type': 'error',
                  'msg': 'bot_access_denied',
                }));
              } catch (_) {}
              try {
                ws.sink.close(4003, 'bot_access_denied');
              } catch (_) {}
              _users.remove(publicKey);
              return;
            }

            final shortId = publicKey.substring(0, 8);
            if (_isKnownBot(publicKey)) {
              _recordBotActivity(publicKey, 'connect',
                  detail: nick.isEmpty ? '@${shortId}' : nick);
            }
            ws.sink.add(jsonEncode({
              'type': 'registered',
              'shortId': shortId,
              'onlineCount': _users.length,
            }));

            final accBlob = _accountBlobs[publicKey];
            if (accBlob != null && accBlob.isNotEmpty) {
              try {
                ws.sink.add(jsonEncode({
                  'type': 'account_sync_blob',
                  'data': accBlob,
                }));
              } catch (_) {}
            }

            _sendChannelDirSnapshot(ws);
            _sendBotDirSnapshot(ws);
            _sendMailboxSnapshot(user!);
            // Send currently online (non-away) peers to the new user
            for (final other in _users.values) {
              if (other.publicKey == publicKey) continue;
              if (other.away) continue; // don't show backgrounded peers as online
              try {
                ws.sink.add(jsonEncode({
                  'type': 'presence',
                  'publicKey': other.publicKey,
                  'online': true,
                  'nick': other.nick,
                  if (other.x25519Key.isNotEmpty) 'x25519': other.x25519Key,
                }));
              } catch (_) {}
            }

            // Notify other users about this new user
            _broadcastPresence(publicKey, true);

            stdout.writeln(
                '[+] ${nick.isEmpty ? shortId : nick} connected (${_users.length} online)');
          } catch (e) {
            ws.sink.add(jsonEncode({'type': 'error', 'msg': 'bad_register'}));
          }
        } else {
          _handleMessage(user!, raw);
        }
      },
      onDone: () {
        if (user != null) {
          final cc = ws.closeCode;
          final cr = ws.closeReason;
          final publicKey = user!.publicKey;
          if (_isKnownBot(publicKey)) {
            _recordBotActivity(publicKey, 'disconnect',
                detail: cc == null
                    ? ''
                    : '$cc${cr == null || cr.isEmpty ? '' : ' $cr'}');
          }
          _users.remove(publicKey);
          _rateLimits.remove(publicKey); // free rate-limit memory on disconnect
          _broadcastPresence(publicKey, false);
          final id = user!.nick.isEmpty ? user!.shortId : user!.nick;
          final detail = cc == null
              ? ''
              : ' [closeCode=$cc${cr == null || cr.isEmpty ? '' : ', $cr'}]';
          stdout
              .writeln('[-] $id disconnected (${_users.length} online)$detail');
        }
      },
      onError: (e) {
        if (user != null) {
          final publicKey = user!.publicKey;
          if (_isKnownBot(publicKey)) {
            _recordBotActivity(publicKey, 'disconnect', detail: 'ws_error');
          }
          _users.remove(publicKey);
          stdout.writeln('[-] ${user!.shortId} ws error: $e');
        }
      },
    );
  }, pingInterval: const Duration(seconds: 25));
}

void _broadcastPresence(String publicKey, bool online) {
  final sourceUser = _users[publicKey];
  final x25519Key = sourceUser?.x25519Key ?? '';
  final nick = sourceUser?.nick ?? '';
  final msg = jsonEncode({
    'type': 'presence',
    'publicKey': publicKey,
    'online': online,
    if (nick.isNotEmpty) 'nick': nick,
    if (x25519Key.isNotEmpty) 'x25519': x25519Key,
  });
  for (final user in _users.values) {
    if (user.publicKey == publicKey) continue;
    try {
      user.ws.sink.add(msg);
    } catch (_) {}
  }
}

// ── Health check / info endpoint ────────────────────────────────

shelf.Response _jsonResponse(Map<String, dynamic> body, {int status = 200}) {
  return shelf.Response(
    status,
    body: jsonEncode(body),
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers':
          'content-type, authorization, x-admin-hash',
    },
  );
}

String? _botIdFromBearerApiToken(String authHeader) {
  if (!authHeader.startsWith('Bearer ')) return null;
  final t = authHeader.substring(7).trim();
  if (t.isEmpty) return null;
  final h = _sha256HexUtf8(t);
  for (final e in _botDirectory.entries) {
    if (e.value['revoked'] == true) continue;
    if ((e.value['apiTokenHash'] as String?) == h) return e.key;
  }
  return null;
}

Future<shelf.Response> _infoHandler(shelf.Request request) async {
  if (request.method == 'OPTIONS') {
    return shelf.Response(
      204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,OPTIONS',
        'access-control-allow-headers':
            'content-type, authorization, x-admin-hash',
      },
    );
  }
  // Durable Google Drive linking: /oauth/google/{start,callback,token}.
  final oauthResp = await handleGoogleOauth(request);
  if (oauthResp != null) return oauthResp;
  if (request.url.path == 'push/public_key') {
    if (!_webPushConfigured) {
      return _jsonResponse({'enabled': false, 'publicKey': ''}, status: 503);
    }
    return _jsonResponse({'enabled': true, 'publicKey': _vapidPublicKey});
  }
  if (request.url.path == 'push/subscribe' && request.method == 'POST') {
    if (!_webPushConfigured) {
      return _jsonResponse({'ok': false, 'error': 'push_not_configured'},
          status: 503);
    }
    try {
      final raw = await request.readAsString();
      final decoded = jsonDecode(raw);
      if (decoded is! Map) {
        return _jsonResponse({'ok': false, 'error': 'bad_json'}, status: 400);
      }
      final publicKey =
          (decoded['publicKey'] as String?)?.trim().toLowerCase() ?? '';
      final subRaw = decoded['subscription'];
      if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(publicKey) || subRaw is! Map) {
        return _jsonResponse({'ok': false, 'error': 'bad_request'},
            status: 400);
      }
      final endpoint = (subRaw['endpoint'] as String?)?.trim() ?? '';
      final keysRaw = subRaw['keys'];
      if (endpoint.isEmpty || keysRaw is! Map) {
        return _jsonResponse({'ok': false, 'error': 'bad_subscription'},
            status: 400);
      }
      final p256dh = _normalizeB64Url((keysRaw['p256dh'] as String?) ?? '');
      final auth = _normalizeB64Url((keysRaw['auth'] as String?) ?? '');
      if (p256dh.isEmpty || auth.isEmpty) {
        return _jsonResponse({'ok': false, 'error': 'bad_keys'}, status: 400);
      }
      _upsertPushSubscription(publicKey, {
        'endpoint': endpoint,
        'keys': {'p256dh': p256dh, 'auth': auth},
        'updatedAt': DateTime.now().millisecondsSinceEpoch,
        if ((decoded['nick'] as String?)?.trim().isNotEmpty ?? false)
          'nick': (decoded['nick'] as String).trim(),
      });
      return _jsonResponse({'ok': true});
    } catch (_) {
      return _jsonResponse({'ok': false, 'error': 'invalid_payload'},
          status: 400);
    }
  }
  if (request.url.path == 'push/test' && request.method == 'POST') {
    if (!_webPushConfigured) {
      return _jsonResponse({'ok': false, 'error': 'push_not_configured'},
          status: 503);
    }
    try {
      final raw = await request.readAsString();
      final decoded = jsonDecode(raw);
      final publicKey = (decoded is Map
              ? (decoded['publicKey'] as String?)
              : null)
          ?.trim()
          .toLowerCase() ??
          '';
      if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(publicKey)) {
        return _jsonResponse({'ok': false, 'error': 'bad_request'},
            status: 400);
      }
      final subs = _pushSubscriptions[publicKey];
      if (subs == null || subs.isEmpty) {
        return _jsonResponse(
            {'ok': false, 'error': 'no_subscription', 'sent': 0});
      }
      var sent = 0;
      final toRemove = <String>{};
      final client = HttpClient();
      try {
        for (final sub in subs) {
          final endpoint = (sub['endpoint'] as String?)?.trim() ?? '';
          if (endpoint.isEmpty) continue;
          try {
            // Payloadless push (Web Push rejects unencrypted payloads → 400).
            final req = await client.postUrl(Uri.parse(endpoint));
            req.headers.set('TTL', '60');
            req.headers.set('Authorization', _vapidAuthHeader(endpoint));
            req.headers.set('Urgency', 'high');
            final resp = await req.close();
            if (resp.statusCode == 404 || resp.statusCode == 410) {
              toRemove.add(endpoint);
            } else if (resp.statusCode >= 200 && resp.statusCode < 300) {
              sent++;
            }
          } catch (_) {}
        }
      } finally {
        client.close(force: true);
      }
      if (toRemove.isNotEmpty) {
        subs.removeWhere(
            (s) => toRemove.contains((s['endpoint'] as String?) ?? ''));
        if (subs.isEmpty) _pushSubscriptions.remove(publicKey);
        _persistPushSubscriptions();
      }
      return _jsonResponse({'ok': sent > 0, 'sent': sent});
    } catch (_) {
      return _jsonResponse({'ok': false, 'error': 'invalid_payload'},
          status: 400);
    }
  }
  if (request.url.path == 'translate') {
    // Прокси Google Translate (gtx). Нужен, потому что браузер блокирует прямой
    // запрос клиента к googleapis (CORS). Сервер ходит сам и отдаёт результат.
    final tl = (request.url.queryParameters['tl'] ?? 'en').trim();
    final q = request.url.queryParameters['q'] ?? '';
    if (q.isEmpty || q.length > 5000) {
      return _jsonResponse({'ok': false, 'error': 'bad_request'}, status: 400);
    }
    try {
      final uri = Uri.https('translate.googleapis.com', '/translate_a/single', {
        'client': 'gtx',
        'sl': 'auto',
        'tl': tl.isEmpty ? 'en' : tl,
        'dt': 't',
        'q': q,
      });
      final client = HttpClient();
      try {
        final req = await client.getUrl(uri);
        req.headers.set('User-Agent', 'Mozilla/5.0 (compatible; RlinkRelay)');
        final resp = await req.close();
        if (resp.statusCode != 200) {
          return _jsonResponse(
              {'ok': false, 'error': 'upstream_${resp.statusCode}'},
              status: 502);
        }
        final body = await resp.transform(utf8.decoder).join();
        final data = jsonDecode(body);
        final sb = StringBuffer();
        if (data is List && data.isNotEmpty && data[0] is List) {
          for (final seg in (data[0] as List)) {
            if (seg is List && seg.isNotEmpty && seg[0] is String) {
              sb.write(seg[0] as String);
            }
          }
        }
        final out = sb.toString();
        if (out.isEmpty) {
          return _jsonResponse({'ok': false, 'error': 'empty'});
        }
        return _jsonResponse({'ok': true, 'text': out});
      } finally {
        client.close(force: true);
      }
    } catch (e) {
      return _jsonResponse({'ok': false, 'error': 'proxy_failed'}, status: 502);
    }
  }
  if (request.url.path == 'health') {
    final peers = _users.values
        .map((u) => {
              'shortId': u.shortId,
              'nick': u.nick,
              'connectedAt': u.connectedAt.toIso8601String(),
            })
        .toList();
    return _jsonResponse({
      'status': 'ok',
      'online': _users.length,
      'peers': peers,
      'uptime': DateTime.now().toIso8601String(),
      'pushConfigured': _webPushConfigured,
      'pushRecipients': _pushSubscriptions.length,
      'adminEnabled': _relayAdminHash.isNotEmpty,
    });
  }

  // ── HTTP Bot API (метаданные; сообщения только WS + E2E) ─────────
  if (request.url.path.startsWith('bot-api/v1/') && request.method == 'POST') {
    final botId = _botIdFromBearerApiToken(
      request.headers['authorization'] ??
          request.headers['Authorization'] ??
          '',
    );
    if (botId == null) {
      return _jsonResponse({'ok': false, 'error': 'unauthorized'}, status: 401);
    }
    final row = _botDirectory[botId];
    if (row == null || row['revoked'] == true || row['blocked'] == true) {
      return _jsonResponse({'ok': false, 'error': 'not_found'}, status: 404);
    }
    void markApiCall(String action) {
      _recordBotActivity(botId, 'api_call', detail: action, persist: false);
      row['updatedAt'] = DateTime.now().millisecondsSinceEpoch;
    }

    try {
      final raw = await request.readAsString();
      final decoded = raw.isEmpty ? <String, dynamic>{} : jsonDecode(raw);
      if (decoded is! Map) {
        return _jsonResponse({'ok': false, 'error': 'bad_json'}, status: 400);
      }
      final action = request.url.path.substring('bot-api/v1/'.length);
      switch (action) {
        case 'setWebhook':
          final url = (decoded['url'] as String?)?.trim() ?? '';
          if (url.isEmpty) {
            row['webhookUrl'] = '';
          } else {
            final u = Uri.tryParse(url);
            if (u == null ||
                !u.hasScheme ||
                (u.scheme != 'https' && u.scheme != 'http')) {
              return _jsonResponse({'ok': false, 'error': 'bad_url'},
                  status: 400);
            }
            if (url.length > 2048) {
              return _jsonResponse({'ok': false, 'error': 'url_too_long'},
                  status: 400);
            }
            row['webhookUrl'] = url;
          }
          markApiCall(action);
          _persistBotDirectory();
          return _jsonResponse({'ok': true});
        case 'deleteWebhook':
          row['webhookUrl'] = '';
          markApiCall(action);
          _persistBotDirectory();
          return _jsonResponse({'ok': true});
        case 'setMyDescription':
          final d = (decoded['description'] as String?)?.trim() ?? '';
          if (d.length > 512) {
            return _jsonResponse({'ok': false, 'error': 'description_too_long'},
                status: 400);
          }
          row['description'] = d;
          markApiCall(action);
          _persistBotDirectory();
          _broadcastBotDirSnapshotToAll();
          return _jsonResponse({'ok': true});
        case 'setMyName':
          final n = (decoded['displayName'] as String?)?.trim() ?? '';
          if (n.isEmpty || n.length > 64) {
            return _jsonResponse({'ok': false, 'error': 'bad_display_name'},
                status: 400);
          }
          row['displayName'] = n;
          markApiCall(action);
          _persistBotDirectory();
          _broadcastBotDirSnapshotToAll();
          return _jsonResponse({'ok': true});
        case 'setMyAvatarUrl':
          final u = (decoded['url'] as String?)?.trim() ?? '';
          if (!_isAllowedBotMediaUrl(u)) {
            return _jsonResponse({'ok': false, 'error': 'bad_url'},
                status: 400);
          }
          row['avatarUrl'] = u;
          markApiCall(action);
          _persistBotDirectory();
          _broadcastBotDirSnapshotToAll();
          return _jsonResponse({'ok': true});
        case 'setMyBannerUrl':
          final bu = (decoded['url'] as String?)?.trim() ?? '';
          if (!_isAllowedBotMediaUrl(bu)) {
            return _jsonResponse({'ok': false, 'error': 'bad_url'},
                status: 400);
          }
          row['bannerUrl'] = bu;
          markApiCall(action);
          _persistBotDirectory();
          _broadcastBotDirSnapshotToAll();
          return _jsonResponse({'ok': true});
        case 'revokeToken':
          final apiToken = _randomUrlToken();
          row['apiTokenHash'] = _sha256HexUtf8(apiToken);
          markApiCall(action);
          _persistBotDirectory();
          return _jsonResponse({'ok': true, 'apiToken': apiToken});
        default:
          return _jsonResponse({'ok': false, 'error': 'unknown_action'},
              status: 404);
      }
    } catch (_) {
      return _jsonResponse({'ok': false, 'error': 'invalid_payload'},
          status: 400);
    }
  }

  return shelf.Response.notFound('Not found');
}

// ── Main ────────────────────────────────────────────────────────

Future<void> main() async {
  final port = int.tryParse(Platform.environment['PORT'] ?? '') ?? 8080;
  _loadRelayAdminConfig();
  _loadAccountBlobs();
  _loadMailbox();
  _loadPushSubscriptions();
  _loadChannelDirectory();
  _loadBotDirectory();

  // Cascade: try WebSocket first, then HTTP info
  final handler = shelf.Cascade().add(_wsHandler()).add(_infoHandler).handler;

  final server = await io.serve(
    handler,
    InternetAddress.anyIPv4,
    port,
  );

  stdout.writeln('══════════════════════════════════════════════');
  stdout.writeln('  Rlink Relay Server v1.0');
  stdout.writeln('  Listening on ws://${server.address.host}:${server.port}');
  stdout.writeln('  Zero-knowledge relay — E2E encrypted only');
  if (_relayAdminHash.isEmpty) {
    stdout.writeln('  Admin bot panel: DISABLED (set RELAY_ADMIN_HASH)');
  } else {
    stdout.writeln('  Admin bot panel: enabled');
  }
  stdout.writeln('══════════════════════════════════════════════');

  // Periodic tombstone cleanup: remove entries older than 7 days.
  Timer.periodic(const Duration(hours: 1), (_) {
    final cutoff = DateTime.now().subtract(const Duration(days: 7));
    _channelDirTombstones
        .removeWhere((k, v) => v < cutoff.millisecondsSinceEpoch);
  });

  // Periodic stats: log connection count and memory usage.
  Timer.periodic(const Duration(minutes: 5), (_) {
    stdout.writeln('[stats] online=${_users.length} '
        'channel_dir=${_channelDirectory.length} '
        'bots=${_botDirectory.length} '
        'packets=$_forwardedPackets '
        'broadcastDeliveries=$_forwardedBroadcastPackets '
        'blobs=$_forwardedBlobs '
        'droppedOversize=$_droppedOversizePackets');
  });
}
