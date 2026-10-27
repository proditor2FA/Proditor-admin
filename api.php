<?php
/**
 * Proditor - JSON-API der multiOTP-Verwaltung (auf dem multiOTP-Master installieren).
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2026 proditor2FA - LGPL-3.0-or-later, siehe COPYING.LESSER
 *
 * Nutzt die multiOTP-Klasse und deren Benutzerdaten direkt, Anmeldung mit dem
 * bestehenden multiOTP-Admin-Passwort. Aenderungen landen in /etc/multiotp/users
 * und werden vom bestehenden rsync an die Klone verteilt.
 *
 * GET  ?action=session            Anmeldestatus + CSRF-Token
 * POST ?action=login|logout
 * GET  ?action=users              Alle Benutzer mit Token-Details
 * GET  ?action=tokens             Freie (keinem Benutzer zugeordnete) Hardware-Tokens
 * GET  ?action=qr&user=...        QR-Code-Seite (HTML) fuer Software-Tokens
 * POST ?action=counter|resync|check|lock|unlock|delete|create
 */

declare(strict_types=1);
error_reporting(E_ERROR | E_PARSE);

const MOTP_DIR      = '/usr/local/bin/multiotp/';
const ETC_DIR       = '/etc/multiotp/';
const MAX_FAILS     = 5;    // Fehl-Logins pro IP ...
const LOCK_SECONDS  = 300;  // ... bevor fuer 5 Minuten gesperrt wird
const MAX_COUNTER   = 2147483647;

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

session_name('MOTPADMIN');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/admin/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function reply(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function fail(string $message, int $status = 400): never
{
    reply(['ok' => false, 'error' => $message], $status);
}

function logged_in(): bool
{
    return !empty($_SESSION['logged']);
}

// Fehl-Login-Zaehler pro IP, unabhaengig vom Session-Cookie
function fail_file(): string
{
    return sys_get_temp_dir() . '/motpadmin-' . md5($_SERVER['REMOTE_ADDR'] ?? '') . '.json';
}

function fail_state(): array
{
    $state = json_decode((string)@file_get_contents(fail_file()), true);
    return is_array($state) ? $state : ['count' => 0, 'since' => time()];
}

function multiotp(): Multiotp
{
    chdir(MOTP_DIR);
    require_once MOTP_DIR . 'multiotp.class.php';
    $m = new Multiotp('DefaultCliEncryptionKey', false, '', ETC_DIR . 'config');
    $m->SetHashSalt(_MULTIOTP_DEFAULT_HASH_SALT_);
    $m->ForceNoDisplayLog();
    $m->SetLogFolder('/var/log/multiotp/');
    $m->SetConfigFolder(ETC_DIR . 'config/');
    $m->SetDdnsFolder(ETC_DIR . 'ddns/');
    $m->SetDevicesFolder(ETC_DIR . 'devices/');
    $m->SetGroupsFolder(ETC_DIR . 'groups/');
    $m->SetTokensFolder(ETC_DIR . 'tokens/');
    $m->SetUsersFolder(ETC_DIR . 'users/');
    $m->SetCacheFolder('/tmp/cache/');
    $m->SetLinuxFileMode('0666');
    $m->ReadConfigData();
    return $m;
}

function audit(Multiotp $m, string $text, string $user): void
{
    $who = $_SERVER['REMOTE_ADDR'] ?? '?';
    $m->WriteLog("Info: Verwaltung (Proditor, $who): $text", false, false, 0, 'Configuration', $user);
}

// Benutzername aus Anfrage pruefen und vorhandenen Benutzer laden
function need_user(Multiotp $m, array $src): string
{
    $user = (string)($src['user'] ?? '');
    if ($user === '' || mb_strlen($user) > 255 || preg_match('/[\x00-\x1F\x7F]/', $user)) {
        fail('Ungültiger Benutzername.');
    }
    if (!$m->CheckUserExists($user, true) || !$m->ReadUserData($user, false, true)) {
        fail("Benutzer \"$user\" gibt es nicht.", 404);
    }
    return $user;
}

function user_info(Multiotp $m, string $user): ?array
{
    if (!$m->ReadUserData($user, false, true)) {
        return null;
    }
    return [
        'user'         => $user,
        'description'  => (string)$m->GetUserDescription(),
        'display_name' => (string)$m->GetUserDisplayName(),
        'email'        => (string)$m->GetUserEmail(),
        'group'        => (string)$m->GetUserGroup(),
        'algorithm'    => (string)$m->GetUserAlgorithm(),
        'digits'       => (int)$m->GetUserTokenNumberOfDigits(),
        'serial'       => (string)$m->GetUserTokenSerialNumber(),
        'last_event'   => (int)$m->GetUserTokenLastEvent(),
        'locked'       => (bool)$m->GetUserLocked(),
        'errors'       => (int)$m->GetUserErrorCounter(),
        'active'       => (bool)$m->GetUserActivated(),
        'synced'       => (bool)$m->GetUserSynchronized(),
        'last_login'   => (int)$m->GetUserLastLogin(),
    ];
}

// Seriennummer -> Benutzer fuer alle bereits zugeordneten Sticks
function used_serials(Multiotp $m): array
{
    $used = [];
    foreach (array_filter(explode("\t", trim((string)$m->GetUsersList())), 'strlen') as $user) {
        if ($m->ReadUserData($user, false, true) && '' !== ($s = (string)$m->GetUserTokenSerialNumber())) {
            $used[mb_strtolower($s)] = $user;
        }
    }
    return $used;
}

$action = (string)($_GET['action'] ?? '');
$body = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) {
        fail('Die Sitzung ist abgelaufen. Lade die Seite neu.', 403);
    }
    $body = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($body)) {
        $body = [];
    }
} elseif (!in_array($action, ['session', 'users', 'tokens', 'qr'], true)) {
    fail('Unbekannte Aktion.', 405);
}

$m = multiotp();

if ($action === 'session') {
    $info = [
        'ok'     => true,
        'logged' => logged_in(),
        'csrf'   => $_SESSION['csrf'],
        'host'   => gethostname(),
    ];
    // Softwarestaende nur fuer angemeldete Admins
    if (logged_in()) {
        $info['multiotp'] = $m->GetVersion();
        $info['php'] = PHP_VERSION;
    }
    reply($info);
}

if ($action === 'login') {
    $state = fail_state();
    if ($state['count'] >= MAX_FAILS && time() - $state['since'] < LOCK_SECONDS) {
        fail('Zu viele Fehlversuche. Warte 5 Minuten und versuche es dann erneut.', 429);
    }
    if ('' === (string)$m->GetConfigAttribute('admin_password_hash')) {
        fail('Es ist kein Admin-Passwort gesetzt. Setze es zuerst in der alten Konsole.', 409);
    }
    if (!$m->CheckAdminPassword((string)($body['password'] ?? ''))) {
        $state = (time() - $state['since'] < LOCK_SECONDS) ? $state : ['count' => 0, 'since' => time()];
        $state['count']++;
        @file_put_contents(fail_file(), json_encode($state));
        usleep(800000);
        $m->WriteLog('Warning: Verwaltung (Proditor): falsches Admin-Passwort von ' . ($_SERVER['REMOTE_ADDR'] ?? '?'), false, false, 0, 'Configuration', '');
        fail('Das Passwort stimmt nicht.', 401);
    }
    @unlink(fail_file());
    session_regenerate_id(true);
    $_SESSION['logged'] = true;
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    reply(['ok' => true, 'csrf' => $_SESSION['csrf']]);
}

if ($action === 'logout') {
    $_SESSION = [];
    session_destroy();
    reply(['ok' => true]);
}

if (!logged_in()) {
    fail('Bitte melde dich an.', 401);
}

switch ($action) {
    case 'users':
        $list = array_filter(explode("\t", trim((string)$m->GetUsersList())), 'strlen');
        $users = [];
        foreach ($list as $user) {
            if (null !== ($info = user_info($m, $user))) {
                $users[] = $info;
            }
        }
        usort($users, fn($a, $b) => strnatcasecmp($a['user'], $b['user']));
        reply(['ok' => true, 'users' => $users]);

    case 'tokens':
        $all = array_filter(explode("\t", trim((string)$m->GetTokensList())), 'strlen');
        $used = used_serials($m);
        $free = array_values(array_filter($all, fn($t) => !isset($used[mb_strtolower($t)])));
        natcasesort($free);
        reply(['ok' => true, 'tokens' => array_values($free)]);

    case 'qr':
        $user = need_user($m, $_GET);
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'");
        echo $m->GenerateHtmlQrCode($user);
        exit;

    case 'counter':
        $user = need_user($m, $body);
        if ($m->GetUserAlgorithm() !== 'hotp') {
            fail('Den Zähler gibt es nur bei HOTP-Tokens.');
        }
        $next = filter_var($body['next'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => MAX_COUNTER]]);
        if (false === $next) {
            fail('Gib eine ganze Zahl ab 1 ein.');
        }
        $old_next = (int)$m->GetUserTokenLastEvent() + 1;
        $m->SetUserTokenLastEvent($next - 1);
        if (!$m->WriteUserData()) {
            fail('Der Zähler konnte nicht gespeichert werden.', 500);
        }
        audit($m, "HOTP-Zaehler von $user von $old_next auf $next gesetzt", $user);
        reply(['ok' => true, 'user' => user_info($m, $user)]);

    case 'resync':
        $user = need_user($m, $body);
        $otp1 = preg_replace('/\D/', '', (string)($body['otp1'] ?? ''));
        $otp2 = preg_replace('/\D/', '', (string)($body['otp2'] ?? ''));
        if ($otp1 === '' || $otp2 === '') {
            fail('Gib zwei aufeinanderfolgende Codes ein.');
        }
        // 14 = resynchronisiert, 0 = beide Codes lagen ohnehin im normalen Fenster
        $result = (int)$m->CheckToken($otp1, $otp2);
        if (14 !== $result && 0 !== $result) {
            fail('Resync fehlgeschlagen: ' . $m->GetErrorText($result));
        }
        audit($m, "Token von $user per Resync synchronisiert", $user);
        reply(['ok' => true, 'user' => user_info($m, $user)]);

    case 'check':
        $user = need_user($m, $body);
        $otp = preg_replace('/\s/', '', (string)($body['otp'] ?? ''));
        if ($otp === '') {
            fail('Gib einen Code ein.');
        }
        $result = (int)$m->CheckToken($otp);
        reply([
            'ok'      => true,
            'valid'   => 0 === $result,
            'message' => 0 === $result ? 'Code gültig.' : $m->GetErrorText($result),
            'user'    => user_info($m, $user),
        ]);

    case 'lock':
    case 'unlock':
        $user = need_user($m, $body);
        if (!($action === 'lock' ? $m->LockUser($user) : $m->UnlockUser($user))) {
            fail('Das hat nicht geklappt.', 500);
        }
        audit($m, ($action === 'lock' ? 'gesperrt: ' : 'entsperrt: ') . $user, $user);
        reply(['ok' => true, 'user' => user_info($m, $user)]);

    case 'delete':
        $user = need_user($m, $body);
        if (($body['confirm'] ?? '') !== $user) {
            fail('Zur Bestätigung muss der Benutzername eingegeben werden.');
        }
        if (!$m->DeleteUser($user)) {
            fail('Der Benutzer konnte nicht gelöscht werden.', 500);
        }
        audit($m, "Benutzer $user geloescht", $user);
        reply(['ok' => true]);

    case 'create':
        $user = trim((string)($body['user'] ?? ''));
        if ($user === '' || mb_strlen($user) > 255 || preg_match('/[\x00-\x1F\x7F\\\\]/', $user)) {
            fail('Gib einen gültigen Benutzernamen ein.');
        }
        if ($m->CheckUserExists($user, true)) {
            fail("Den Benutzer \"$user\" gibt es schon.", 409);
        }
        $description = trim((string)($body['description'] ?? ''));
        $email = trim((string)($body['email'] ?? ''));
        $pin = trim((string)($body['pin'] ?? ''));
        $prefix = ('' !== $pin) ? 1 : 0;  // eine vorhandene PIN muss immer vor dem Code eingegeben werden
        $kind = (string)($body['kind'] ?? '');
        switch ($kind) {
            case 'stick':  // Proditor-Stick: importierter HOTP-Token, Auswahl ueber Seriennummer
                $serial = mb_strtolower(trim((string)($body['serial'] ?? '')));
                if ($serial === '') {
                    fail('Gib die Seriennummer des Proditor-Sticks ein.');
                }
                if (!$m->ReadTokenData($serial)) {
                    fail("Einen Stick mit der Seriennummer \"$serial\" gibt es nicht. Ist er importiert?");
                }
                if ('hotp' !== mb_strtolower((string)$m->GetTokenAlgorithm())) {
                    fail("Der Token \"$serial\" ist kein HOTP-Stick.");
                }
                $owner = used_serials($m)[$serial] ?? null;
                if (null !== $owner) {
                    fail("Der Stick \"$serial\" gehört schon zu $owner.", 409);
                }
                $ok = true === $m->CreateUserFromToken($user, $serial, $email, '', $pin, $prefix, $description);
                break;
            case 'totp':   // App mit QR-Code
                $ok = (bool)$m->FastCreateUser($user, $email, '', $prefix, 'totp', 1, $description, '*DEFAULT*', 0, $pin);
                break;
            case 'without2fa':
                $ok = (bool)$m->FastCreateUser($user, $email, '', 0, 'without2fa', 1, $description, '*DEFAULT*', 0, '');
                break;
            default:
                fail('Wähle Proditor-Stick, QR-Code oder Without2FA.');
        }
        if (!$ok || !$m->CheckUserExists($user, true)) {
            fail('Der Benutzer konnte nicht angelegt werden.', 500);
        }
        audit($m, "Benutzer $user angelegt ($kind)", $user);
        reply(['ok' => true, 'user' => user_info($m, $user)]);
}

fail('Unbekannte Aktion.', 404);
