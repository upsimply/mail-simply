<?php

declare(strict_types=1);

use MailSimply\Http;
use MailSimply\Log;
use MailSimply\LoginThrottle;
use MailSimply\Session;
use MailSimply\SignOn;

$config = require dirname(__DIR__).'/bootstrap.php';

mail_simply_headers();

$session = new Session($config);

$refuse = static function () use ($config): never {
    $lang = Http::lang($config);
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo $lang->get('This sign-in link is invalid, has expired or has already been used. Open webmail again from your control panel.');
    exit;
};

// Sign-on bound to this browser starts here: a proof goes into a cookie, and
// the browser goes to the panel with its hash, to come back with a token that
// only signs in this browser. Anything else the panel's link asked for (which
// mailbox, say) is passed along as it is.
if (isset($_GET['start'])) {
    $issueUrl = $config->string('sso.issue_url');

    if ($issueUrl === '' || ! $config->singleSignOn()) {
        $refuse();
    }

    $query = http_build_query([...array_diff_key($_GET, ['start' => true, 'binding' => true]), 'binding' => $session->startSignOn()]);

    header('Location: '.$issueUrl.(str_contains($issueUrl, '?') ? '&' : '?').$query);
    exit;
}

$token = (string) ($_GET['token'] ?? '');

// Every token redeemed is a request to the panel, which only answers this host
// so often; a client sending made-up tokens would otherwise spend that for
// everybody. Counted per client, with the login form's per-client limit.
$throttle = new LoginThrottle($config->string('storage.throttle'), 0, $config->int('login.max_attempts_per_client'));
$client = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
$mailbox = null;

if (! $throttle->blocked('', $client)) {
    try {
        $mailbox = (new SignOn($config))->redeem($token, $session->signOnProof());
    } catch (Throwable $e) {
        Log::error('Redeeming a sign-on token failed.', ['error' => $e->getMessage()]);
    }
}

if ($mailbox === null) {
    // A reload of the sign-on URL after it was spent lands back in the
    // session it already opened rather than on an error.
    if ($session->grant() !== null) {
        header('Location: ./');
        exit;
    }

    $throttle->clientFailed($client);
    $refuse();
}

// A token for another mailbox replaces the session already open: the
// customer has just asked the panel for this one.
$session->signIn($mailbox['address'], $mailbox['name'], null);

header('Location: ./');
