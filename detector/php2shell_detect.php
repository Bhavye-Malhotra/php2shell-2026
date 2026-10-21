<?php
/*
 * php2shell-detect.php — on-host vulnerability-detection probe for
 * CVE-2026-109618 / CVE-2026-109619 ("php2shell").
 *
 * Detection logic derives directly from the security-fix commit 506e87fa7
 * ("Avoid state corruption via bailout"), which patches both CVEs:
 *
 *   1) The fix introduces a NEW INI directive 'memory_hard_limit_percent'.
 *      ini_get() returns FALSE for unknown directives. Presence of the
 *      directive is definitive proof the fix is in the binary, because the
 *      fix and only the fix registers it.
 *   2) Fixed release map: >= 8.2.35, >= 8.3.36, >= 8.4.27, >= 8.4.27 / >=8.5.12.
 *      Used as belt-and-braces check in case a distro backported the fix while
 *      keeping the reported version (common for LTS-packaged PHP).
 *   3) Risk modifiers (not decisive, but affect practicality of exploits):
 *      - session.upload_progress.enabled: enables an application-independent
 *        producer for both the session-state case (CVE-2026-109619) and the
 *        OOM-callback case (CVE-2026-109618 trigger convenience).
 *      - fatal_error_backtraces (PHP 8.5): the vend-acknowledged strongest
 *        producer for CVE-2026-109619. Not present on < 8.5.
 *
 * SAFETY: pure introspection. No OOM triggering, no memory demolition, no
 *         worker mutation. Safe to run persistently in production.
 *
 * Usage:
 *   php php2shell-detect.php            # human-readable verdict
 *   php php2shell-detect.php --json     # machine-readable
 *   php php2shell-detect.php --no-exit  # always exit 0 (for wrapper scripts)
 *
 * Exit codes (for scripts): 0 patched | 2 vulnerable | 3 inconclusive
 */

$WANT_JSON = in_array('--json', $argv, true);
$NO_EXIT   = in_array('--no-exit', $argv, true);

ini_set('display_errors', '0');
error_reporting(E_ALL ^ E_DEPRECATED);

$version    = phpversion();
$m = explode('.', $version);
$major = (int) $m[0];
$minor = (int) ($m[1] ?? 0);
if (version_compare($version, '8.6.0-dev', '>=')) {
    $branch = '8.6';
} elseif ($major === 8) {
    $branch = '8.' . $minor;
} else {
    $branch = 'other';
}

$FIXED = [
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
];

// 1) Primary signal: INI key that only exists WITH the patch
$has_hard_limit_key = ini_get('memory_hard_limit_percent') !== false;

// 2) Belt-and-braces: known-fixed version map
$verdict_version = null;
if (isset($FIXED[$branch])) {
    $verdict_version = version_compare($version, $FIXED[$branch], '>=') ? 'fixed-version' : 'affected-version';
} elseif ($branch === 'other') {
    $verdict_version = 'eol-or-unsupported';
} else {
    $verdict_version = 'indeterminate (' . $branch . ')';
}

function ini_bool($name) {
    $v = ini_get($name);
    if ($v === false) {
        return false;
    }
    $v = strtolower(trim((string) $v));
    return in_array($v, ['1', 'on', 'true', 'yes', 'y'], true);
}

// 3) Risk modifiers
$upload_progress = ini_bool('session.upload_progress.enabled');
$strict_mode     = ini_bool('session.use_strict_mode');
$fbt_present     = ini_get('fatal_error_backtraces') !== false;
$fbt_value       = $fbt_present ? ini_get('fatal_error_backtraces') : null;

// 4) Verdict logic
//    - INI marker present            => binary contains the fix
//    - INI marker absent + version <= affected ceiling => vulnerable
//    - INI marker absent + version >= fixed            => patched-from-vendor (marker might be off? no, fix is canonical) still OK
$patched = $has_hard_limit_key || $verdict_version === 'fixed-version';
$verdict = $patched ? 'PATCHED' : ($verdict_version === 'affected-version' || $verdict_version === 'eol-or-unsupported' ? 'VULNERABLE' : 'INCONCLUSIVE');

$exit = $NO_EXIT ? 0 : ($verdict === 'PATCHED' ? 0 : ($verdict === 'VULNERABLE' ? 2 : 3));

$result = [
    'cve'                   => ['CVE-2026-109618', 'CVE-2026-109619'],
    'php_version'           => $version,
    'branch'                => $branch,
    'binary_has_fix_ini_key'=> $has_hard_limit_key,
    'version_map_verdict'   => $verdict_version,
    'upload_progress_enabled' => $upload_progress,
    'session_use_strict_mode' => $strict_mode,
    'fatal_error_backtraces' => $fbt_value,
    'verdict'               => $verdict,
];

if ($WANT_JSON) {
    $result['note'] = 'Detective signals: INI key memory_hard_limit_percent (present only with fix commit 506e87fa7), plus fixed-release map and upload_progress/fatal_error_backtraces risk modifiers.';
    echo json_encode($result, JSON_PRETTY_PRINT), PHP_EOL;
    exit($exit);
}

echo "== php2shell detector (CVE-2026-109618 / CVE-2026-109619) ==\n";
echo "PHP version:                 {$version} (branch {$branch})\n";
echo "INI memory_hard_limit_percent: " . ($has_hard_limit_key ? 'PRESENT -> fix commit 506e87fa7 is compiled in' : 'ABSENT') . "\n";
echo "Version map:                 {$verdict_version}" .
     ($verdict_version === 'fixed-version' ? " (>= {$FIXED[$branch]} => patched)" : '') . "\n";
echo "session.upload_progress:     " . ($upload_progress ? 'ENABLED (exposure amplifier)' : 'disabled') . "\n";
echo "session.use_strict_mode:     " . ($strict_mode ? 'enabled (hardening)' : 'OFF') . "\n";
echo "fatal_error_backtraces:      " . ($fbt_value === null ? 'n/a (not 8.5+)' : var_export($fbt_value, true)) . "\n";
echo "----------------------------------------------------------------\n";
echo "VERDICT: {$verdict}\n";

if ($verdict !== 'PATCHED') {
    echo "\nRecommended interim mitigations (per GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp):\n";
    echo "  * session.upload_progress.enabled = 0   (remove producer/consumer path)\n";
    if ($fbt_value !== null && ini_bool('fatal_error_backtraces')) {
        echo "  * fatal_error_backtraces = 0            (remove strongest 619 producer)\n";
    }
    echo "  * Keep memory limits finite but soft; do NOT use RLIMIT_AS/RLIMIT_DATA\n";
    echo "  * Patched releases: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12\n";
} else {
    echo "\nBinary carries the official fix. Keep upload_progress/fatal_error_backtraces posture as defense-in-depth.\n";
}
exit($exit);
