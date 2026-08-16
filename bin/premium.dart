import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:shelf/shelf.dart' as shelf;

// ── Rlink Premium subscriptions (YooKassa) ───────────────────────────────────
// The relay is the only place a subscription exists: the client's long public
// key is the account id, and the expiry lives here, so reinstalling the app or
// switching devices keeps the subscription.
//
//   POST premium/create   {user_id, plan, email?}  -> {payment_id, confirmation_url}
//   POST premium/check    {payment_id}             -> {active, until_ms}
//   POST premium/webhook  <YooKassa notification>  -> 200
//   GET  premium/status?user_id=<hex>              -> {active, until_ms}
//
// A payment is only ever applied after re-fetching it from the YooKassa API,
// so a forged webhook (or a forged /check) can't grant anything. Prices live
// here too — the client never sends an amount.
//
// Env: YOOKASSA_SHOP_ID, YOOKASSA_SECRET_KEY, PREMIUM_RETURN_URL.

String get _shopId => Platform.environment['YOOKASSA_SHOP_ID'] ?? '';
String get _secretKey => Platform.environment['YOOKASSA_SECRET_KEY'] ?? '';
String get _returnUrl =>
    Platform.environment['PREMIUM_RETURN_URL'] ?? 'https://rendergames.ru/rlink_premium';

bool get premiumConfigured => _shopId.isNotEmpty && _secretKey.isNotEmpty;

/// Plan -> (price in roubles, days added, human name).
const _plans = <String, ({String amount, int days, String title})>{
  'month': (amount: '50.00', days: 30, title: 'Rlink Premium — 1 месяц'),
  'year': (amount: '500.00', days: 365, title: 'Rlink Premium — 1 год'),
};

// Overridable so the logic can be exercised outside the container.
final File _store =
    File(Platform.environment['PREMIUM_STORE'] ?? '/app/data/premium.json');

Map<String, dynamic> _load() {
  try {
    if (_store.existsSync()) {
      return jsonDecode(_store.readAsStringSync()) as Map<String, dynamic>;
    }
  } catch (_) {}
  return <String, dynamic>{};
}

void _save(Map<String, dynamic> m) {
  try {
    _store.parent.createSync(recursive: true);
    _store.writeAsStringSync(jsonEncode(m));
  } catch (_) {}
}

Map<String, dynamic> _subs(Map<String, dynamic> s) =>
    (s['subs'] as Map<String, dynamic>?) ?? (s['subs'] = <String, dynamic>{});

Map<String, dynamic> _payments(Map<String, dynamic> s) =>
    (s['payments'] as Map<String, dynamic>?) ??
    (s['payments'] = <String, dynamic>{});

shelf.Response _json(Map<String, dynamic> m, {int status = 200}) =>
    shelf.Response(status,
        body: jsonEncode(m),
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
        });

final _rnd = Random.secure();

String _idempotenceKey() =>
    List.generate(16, (_) => _rnd.nextInt(256).toRadixString(16).padLeft(2, '0'))
        .join();

/// A user id is a 64-hex-char public key. Anything else is rejected so the
/// store can't be filled with junk keys.
bool _validUserId(String s) =>
    s.length == 64 && RegExp(r'^[0-9a-f]+$').hasMatch(s);

int _untilMsFor(Map<String, dynamic> store, String userId) =>
    ((_subs(store)[userId] as Map<String, dynamic>?)?['until_ms'] as num?)
        ?.toInt() ??
    0;

// ── Admin grants ─────────────────────────────────────────────────────────────
// Used by the relay admin panel over the WebSocket (see admin_premium_* in
// server.dart) to hand out Premium without a payment.

/// Current expiry for [userId], 0 when there is none.
int premiumUntilMs(String userId) => _untilMsFor(_load(), userId.toLowerCase());

/// Adds [days] to [userId]'s subscription, stacking onto whatever time is
/// left. Returns the new expiry, or -1 when the id isn't a valid public key.
int adminGrantPremium(String userId, int days) {
  final id = userId.trim().toLowerCase();
  if (!_validUserId(id) || days <= 0) return -1;
  final store = _load();
  final base = max(DateTime.now().millisecondsSinceEpoch, _untilMsFor(store, id));
  final until = base + days * 86400000;
  _subs(store)[id] = {
    'until_ms': until,
    'updated': DateTime.now().toIso8601String(),
    'source': 'admin',
  };
  _save(store);
  return until;
}

/// Drops [userId]'s subscription entirely.
bool adminRevokePremium(String userId) {
  final id = userId.trim().toLowerCase();
  if (!_validUserId(id)) return false;
  final store = _load();
  _subs(store).remove(id);
  _save(store);
  return true;
}

/// Every subscription, newest expiry first — what the admin panel lists.
List<Map<String, dynamic>> premiumAll() {
  final entries = _subs(_load()).entries.toList();
  final out = entries
      .map((e) => {
            'user_id': e.key,
            'until_ms': ((e.value as Map)['until_ms'] as num?)?.toInt() ?? 0,
            'source': (e.value as Map)['source'] ?? 'payment',
            'updated': (e.value as Map)['updated'] ?? '',
          })
      .toList();
  out.sort((a, b) => (b['until_ms'] as int).compareTo(a['until_ms'] as int));
  return out;
}

Future<Map<String, dynamic>?> _yooKassa(
  String method,
  String path, {
  Map<String, dynamic>? body,
  String? idempotenceKey,
}) async {
  final client = HttpClient();
  try {
    final uri = Uri.parse('https://api.yookassa.ru/v3$path');
    final req = method == 'POST'
        ? await client.postUrl(uri)
        : await client.getUrl(uri);
    final auth = base64Encode(utf8.encode('$_shopId:$_secretKey'));
    req.headers.add('authorization', 'Basic $auth');
    if (idempotenceKey != null) {
      req.headers.add('Idempotence-Key', idempotenceKey);
    }
    if (body != null) {
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(body));
    }
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    final decoded = jsonDecode(text);
    if (decoded is Map<String, dynamic>) {
      if (resp.statusCode >= 200 && resp.statusCode < 300) return decoded;
      return {'error': 'http_${resp.statusCode}', ...decoded};
    }
    return {'error': 'http_${resp.statusCode}', 'detail': text};
  } catch (e) {
    return {'error': 'exception', 'detail': '$e'};
  } finally {
    client.close(force: true);
  }
}

/// Adds the plan's days to the user's subscription. Extending an active
/// subscription stacks onto the remaining time instead of resetting it, so
/// buying more time early never costs the user days.
///
/// Idempotent: a payment already marked applied is a no-op, which is what
/// makes the webhook and /check safe to both fire for the same payment.
int _applyPayment(Map<String, dynamic> store, String paymentId) {
  final rec = _payments(store)[paymentId] as Map<String, dynamic>?;
  if (rec == null) return 0;
  // A gift funds someone else's subscription: the payer created the payment,
  // but the days land on gift_to.
  final giftTo = (rec['gift_to'] as String? ?? '').trim();
  final beneficiary = giftTo.isNotEmpty ? giftTo : (rec['user_id'] as String? ?? '');
  final plan = _plans[rec['plan'] as String? ?? ''];
  if (beneficiary.isEmpty || plan == null) return 0;
  if (rec['applied'] == true) return _untilMsFor(store, beneficiary);

  final now = DateTime.now().millisecondsSinceEpoch;
  final base = max(now, _untilMsFor(store, beneficiary));
  final until = base + plan.days * 86400000;
  _subs(store)[beneficiary] = {
    'until_ms': until,
    'updated': DateTime.now().toIso8601String(),
    if (giftTo.isNotEmpty) 'gifted_by': rec['user_id'],
  };
  rec['applied'] = true;
  rec['applied_at'] = DateTime.now().toIso8601String();
  _save(store);
  return until;
}

/// Fetches the payment from YooKassa and applies it if it really succeeded.
/// Never trusts a status that arrived over the wire.
Future<int> _settle(String paymentId) async {
  final store = _load();
  final rec = _payments(store)[paymentId] as Map<String, dynamic>?;
  if (rec == null) return 0;
  if (rec['applied'] == true) {
    return _untilMsFor(store, rec['user_id'] as String? ?? '');
  }
  final payment = await _yooKassa('GET', '/payments/$paymentId');
  if (payment == null || payment['status'] != 'succeeded') return 0;
  return _applyPayment(store, paymentId);
}

/// Handles `premium/*`. Returns null for any other path so the caller
/// continues its normal dispatch.
Future<shelf.Response?> handlePremium(shelf.Request request) async {
  final path = request.url.path; // shelf paths have no leading slash
  if (!path.startsWith('premium/')) return null;

  // Status is readable without a configured shop — clients rely on it to know
  // whether an existing subscription is still alive.
  if (path == 'premium/status') {
    final userId = (request.url.queryParameters['user_id'] ?? '').toLowerCase();
    if (!_validUserId(userId)) {
      return _json({'ok': false, 'error': 'bad_user_id'}, status: 400);
    }
    final until = _untilMsFor(_load(), userId);
    return _json({
      'ok': true,
      'active': until > DateTime.now().millisecondsSinceEpoch,
      'until_ms': until,
    });
  }

  if (!premiumConfigured) {
    return _json({'ok': false, 'error': 'premium_not_configured'}, status: 503);
  }

  if (path == 'premium/create' && request.method == 'POST') {
    Map<String, dynamic> body;
    try {
      body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    } catch (_) {
      return _json({'ok': false, 'error': 'bad_json'}, status: 400);
    }
    final userId = (body['user_id'] as String? ?? '').trim().toLowerCase();
    final planKey = (body['plan'] as String? ?? '').trim();
    final plan = _plans[planKey];
    // Gift: the days go to gift_to instead of the payer (birthday present).
    final giftTo = (body['gift_to'] as String? ?? '').trim().toLowerCase();
    if (!_validUserId(userId)) {
      return _json({'ok': false, 'error': 'bad_user_id'}, status: 400);
    }
    if (giftTo.isNotEmpty && !_validUserId(giftTo)) {
      return _json({'ok': false, 'error': 'bad_gift_to'}, status: 400);
    }
    if (plan == null) {
      return _json({'ok': false, 'error': 'bad_plan'}, status: 400);
    }

    final payload = <String, dynamic>{
      'amount': {'value': plan.amount, 'currency': 'RUB'},
      'capture': true,
      'confirmation': {'type': 'redirect', 'return_url': _returnUrl},
      'description': giftTo.isNotEmpty ? '${plan.title} (подарок)' : plan.title,
      'metadata': {
        'user_id': userId,
        'plan': planKey,
        if (giftTo.isNotEmpty) 'gift_to': giftTo,
      },
    };
    // 54-ФЗ receipt, only when the buyer gave an email to send it to.
    final email = (body['email'] as String? ?? '').trim();
    if (email.contains('@')) {
      payload['receipt'] = {
        'customer': {'email': email},
        'items': [
          {
            'description': plan.title,
            'quantity': '1.00',
            'amount': {'value': plan.amount, 'currency': 'RUB'},
            'vat_code': 1,
            'payment_subject': 'service',
            'payment_mode': 'full_payment',
          }
        ],
      };
    }

    final payment = await _yooKassa('POST', '/payments',
        body: payload, idempotenceKey: _idempotenceKey());
    final paymentId = payment?['id'] as String?;
    final url = (payment?['confirmation'] as Map?)?['confirmation_url'] as String?;
    if (paymentId == null || url == null) {
      return _json({
        'ok': false,
        'error': 'create_failed',
        'detail': payment?['error'] ?? payment?['description'],
      }, status: 502);
    }

    final store = _load();
    _payments(store)[paymentId] = {
      'user_id': userId,
      'plan': planKey,
      if (giftTo.isNotEmpty) 'gift_to': giftTo,
      'applied': false,
      'created': DateTime.now().toIso8601String(),
    };
    _save(store);

    return _json({'ok': true, 'payment_id': paymentId, 'confirmation_url': url});
  }

  // Client-driven settlement — makes the flow work even where the webhook
  // can't reach us, and gives the app an immediate answer after the redirect.
  if (path == 'premium/check' && request.method == 'POST') {
    Map<String, dynamic> body;
    try {
      body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    } catch (_) {
      return _json({'ok': false, 'error': 'bad_json'}, status: 400);
    }
    final paymentId = (body['payment_id'] as String? ?? '').trim();
    if (paymentId.isEmpty) {
      return _json({'ok': false, 'error': 'no_payment_id'}, status: 400);
    }
    await _settle(paymentId);
    // Report the PAYER's own subscription (a gift doesn't change it) plus
    // whether this payment went through and whether it was a gift, so the
    // app can send the card without granting the payer premium.
    final store = _load();
    final rec = _payments(store)[paymentId] as Map<String, dynamic>?;
    final gift = (rec?['gift_to'] as String? ?? '').isNotEmpty;
    final applied = rec?['applied'] == true;
    final payerUntil = _untilMsFor(store, rec?['user_id'] as String? ?? '');
    return _json({
      'ok': true,
      'applied': applied,
      'gift': gift,
      'active': payerUntil > DateTime.now().millisecondsSinceEpoch,
      'until_ms': payerUntil,
    });
  }

  if (path == 'premium/webhook' && request.method == 'POST') {
    // Always 200 — YooKassa retries anything else, and the body is only a
    // hint: _settle re-fetches the real status from the API.
    try {
      final body =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final id = (body['object'] as Map?)?['id'] as String?;
      if (id != null) await _settle(id);
    } catch (_) {}
    return _json({'ok': true});
  }

  return _json({'ok': false, 'error': 'unknown_premium_path'}, status: 404);
}
