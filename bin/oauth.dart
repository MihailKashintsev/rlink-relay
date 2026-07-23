import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart' as shelf;

// ── Google OAuth backend (durable Drive linking) ─────────────────────────────
// Auth-code + offline flow. The relay holds the client secret and the refresh
// token; clients only ever receive short-lived access tokens via /token.
//
//   GET  oauth/google/start?p=<pairing>      -> 302 to Google consent
//   GET  oauth/google/callback?code&state    -> exchange code, store refresh
//   GET  oauth/google/token?p=<pairing>      -> fresh access token (auto-refresh)
//
// Env: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, OAUTH_REDIRECT_BASE.

String get _clientId => Platform.environment['GOOGLE_CLIENT_ID'] ?? '';
String get _clientSecret => Platform.environment['GOOGLE_CLIENT_SECRET'] ?? '';
String get _redirectBase => (Platform.environment['OAUTH_REDIRECT_BASE'] ??
        'https://185.244.172.90.nip.io')
    .replaceAll(RegExp(r'/+$'), '');
String get _redirectUri => '$_redirectBase/oauth/google/callback';
const _scope = 'https://www.googleapis.com/auth/drive.file';

final File _store = File('/app/data/google_oauth.json');

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
    _store.writeAsStringSync(jsonEncode(m));
  } catch (_) {}
}

String _esc(String s) => const HtmlEscape().convert(s);

shelf.Response _html(String body, {int status = 200}) => shelf.Response(status,
    body: body, headers: {'content-type': 'text/html; charset=utf-8'});

shelf.Response _json(Map<String, dynamic> m, {int status = 200}) =>
    shelf.Response(status,
        body: jsonEncode(m),
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
        });

Future<Map<String, dynamic>?> _postForm(String url, Map<String, String> form) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse(url));
    req.headers.contentType =
        ContentType('application', 'x-www-form-urlencoded', charset: 'utf-8');
    final body = form.entries
        .map((e) =>
            '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
        .join('&');
    req.write(body);
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    try {
      final decoded = jsonDecode(text);
      if (decoded is Map<String, dynamic>) {
        if (resp.statusCode >= 200 && resp.statusCode < 300) return decoded;
        return {'error': 'http_${resp.statusCode}', ...decoded};
      }
    } catch (_) {}
    return {'error': 'http_${resp.statusCode}', 'detail': text};
  } catch (e) {
    return {'error': 'exception', 'detail': '$e'};
  } finally {
    client.close(force: true);
  }
}

Future<String?> _emailFor(String accessToken) async {
  final client = HttpClient();
  try {
    final req = await client
        .getUrl(Uri.parse('https://www.googleapis.com/oauth2/v3/userinfo'));
    req.headers.add('authorization', 'Bearer $accessToken');
    final resp = await req.close();
    final text = await resp.transform(utf8.decoder).join();
    if (resp.statusCode == 200) {
      final m = jsonDecode(text) as Map<String, dynamic>;
      return m['email'] as String?;
    }
  } catch (_) {
  } finally {
    client.close(force: true);
  }
  return null;
}

/// Handles `oauth/google/*`. Returns null for any other path so the caller
/// continues its normal dispatch.
Future<shelf.Response?> handleGoogleOauth(shelf.Request request) async {
  final path = request.url.path; // shelf paths have no leading slash
  if (!path.startsWith('oauth/google/')) return null;

  if (_clientId.isEmpty) {
    return _html('<h3>OAuth не настроен: нет GOOGLE_CLIENT_ID на сервере.</h3>',
        status: 503);
  }

  // 1) start -> redirect to Google consent
  if (path == 'oauth/google/start') {
    final p = request.url.queryParameters['p'] ?? '';
    if (p.isEmpty) return _html('<h3>Нет параметра p.</h3>', status: 400);
    final auth = Uri.https('accounts.google.com', '/o/oauth2/v2/auth', {
      'client_id': _clientId,
      'redirect_uri': _redirectUri,
      'response_type': 'code',
      'scope': _scope,
      'access_type': 'offline',
      'include_granted_scopes': 'true',
      'prompt': 'consent',
      'state': p,
    });
    return shelf.Response.found(auth.toString());
  }

  if (_clientSecret.isEmpty) {
    return _html(
        '<h3>OAuth не настроен: нет GOOGLE_CLIENT_SECRET на сервере.</h3>',
        status: 503);
  }

  // 2) callback -> exchange the code for tokens, store the refresh token
  if (path == 'oauth/google/callback') {
    final q = request.url.queryParameters;
    final err = q['error'];
    if (err != null) {
      return _html('<h3>Google вернул ошибку: ${_esc(err)}</h3>', status: 400);
    }
    final code = q['code'] ?? '';
    final p = q['state'] ?? '';
    if (code.isEmpty || p.isEmpty) {
      return _html('<h3>Нет code/state.</h3>', status: 400);
    }
    final tok = await _postForm('https://oauth2.googleapis.com/token', {
      'code': code,
      'client_id': _clientId,
      'client_secret': _clientSecret,
      'redirect_uri': _redirectUri,
      'grant_type': 'authorization_code',
    });
    if (tok == null || tok['error'] != null || tok['access_token'] == null) {
      return _html(
          '<h3>Не удалось обменять код: ${_esc(tok?['error']?.toString() ?? 'unknown')}</h3>',
          status: 400);
    }
    final refresh = tok['refresh_token'] as String?;
    final access = tok['access_token'] as String;
    final expiresIn = (tok['expires_in'] as num?)?.toInt() ?? 3600;
    final email = await _emailFor(access) ?? '';
    final store = _load();
    final prev = store[p] as Map<String, dynamic>?;
    store[p] = {
      'refresh_token': refresh ?? prev?['refresh_token'],
      'access_token': access,
      'expiry_ms':
          DateTime.now().millisecondsSinceEpoch + (expiresIn - 60) * 1000,
      'email': email,
      'updated': DateTime.now().toIso8601String(),
    };
    _save(store);
    return _html('<!doctype html><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<div style="font-family:-apple-system,sans-serif;max-width:440px;margin:48px auto;text-align:center;color:#0f172a">'
        '<h2 style="color:#0d9488">Готово ✓</h2>'
        '<p>Аккаунт <b>${_esc(email)}</b> привязан к Rlink.</p>'
        '<p>Вернитесь в приложение — оно подхватит привязку автоматически.</p>'
        '</div>');
  }

  // 3) token -> return a fresh access token (refresh server-side if needed)
  if (path == 'oauth/google/token') {
    final p = request.url.queryParameters['p'] ?? '';
    if (p.isEmpty) return _json({'ok': false, 'error': 'no_pairing'}, status: 400);
    final store = _load();
    final rec = store[p] as Map<String, dynamic>?;
    if (rec == null) {
      return _json({'ok': false, 'error': 'not_linked'}, status: 404);
    }
    final now = DateTime.now().millisecondsSinceEpoch;
    var access = rec['access_token'] as String?;
    final expiry = (rec['expiry_ms'] as num?)?.toInt() ?? 0;
    if (access == null || now >= expiry) {
      final refresh = rec['refresh_token'] as String?;
      if (refresh == null || refresh.isEmpty) {
        return _json({'ok': false, 'error': 'no_refresh'}, status: 400);
      }
      final tok = await _postForm('https://oauth2.googleapis.com/token', {
        'client_id': _clientId,
        'client_secret': _clientSecret,
        'refresh_token': refresh,
        'grant_type': 'refresh_token',
      });
      if (tok == null || tok['access_token'] == null) {
        return _json(
            {'ok': false, 'error': 'refresh_failed', 'detail': tok?['error']},
            status: 400);
      }
      access = tok['access_token'] as String;
      final expiresIn = (tok['expires_in'] as num?)?.toInt() ?? 3600;
      rec['access_token'] = access;
      rec['expiry_ms'] = now + (expiresIn - 60) * 1000;
      store[p] = rec;
      _save(store);
    }
    return _json({
      'ok': true,
      'access_token': access,
      'expiry_ms': rec['expiry_ms'],
      'email': rec['email'] ?? '',
    });
  }

  return _html('<h3>Неизвестный путь OAuth.</h3>', status: 404);
}
