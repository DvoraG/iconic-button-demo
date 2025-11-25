<?php
/**
 * Restricted plugin download for WordPress Playground only
 */

// Load config
define('CONFIG_LOADED', true);
$config = require dirname(__DIR__) . 'config/demo-config.php';

// CORS header
$allowedOrigins = $config['security']['allowed_origins'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed_origin) || $origin === 'null') {
    header('Access-Control-Origin: ' . ($origin ?: '*'));
}

header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-WP-Playground');

// OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Allow GET requests only
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    exit('Method Not Allowed');
}

// Security check
$isAllowed = false;
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$token = $_GET['token'] ?? '';

// 1 - Check referrer (must be playground.wordpress.net)
foreach ($config['security']['allowed_referers'] as $allowedReferer) {
    if (strpos($referer, $allowedReferer) !== false) {
        $isAllowed = true;
        break;
    }
}

// 2 - Check user-agent (specific playground user-agent)
if (strpos($userAgent, 'WordPress') !== false ||
    strpos($userAgent, 'playground') !== false) {
    $isAllowed = true;
}

// 3 - Check time based token
$validToken = hash('sha256', $config['security']['token_salt'] . gmdate('Y-m-d-H'));
if ($token === $validToken) {
    $isAllowed = true;
}

// 4 - Check header origin (sometimes 'null' is send by Playground)
if (in_array($origin, $allowed_origin) || $origin === null) {
    $isAllowed = true;
}

// Refuse access, if none of the above conditions is met
if (!$isAllowed) {
    // Log suspicious attempt of gaining access
    logAccessDenied($config, $referer, $userAgent, $token);
    http_response_code(403);
    exit('Access Denied');
}

// Rate limiting (max. 10 downloads per IP per hour)
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!checkRateLimit($config, $ip)) {
    http_response_code(429);
    exit('Too Many Requests');
}

// Log successful download
logDownload($config, $ip, $referer);

// Send the file
header('Content-Type: application/zip');
header('Content-Length: ' . filesize($pluginPath));
header('Content-Disposition: attachment; filename="' . $config['plugin']['zip_filename'] . '"');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Robots-Tag: noindex, nofollow');

// Transfer the file in chunks 
$handle = fopen($pluginPath, 'rb');
if ($handle) {
    while (!feof($handle)) {
        echo fread($handle, 8192);
        flush();
    }
    fclose($handle);
}

exit;

// === Helper functions ===

function anonymizeIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        $parts[3] = '*';
        return implode('.', $parts);
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $parts = explode(':', $ip);
        $parts[count($parts) - 1] = '*';
        return implode(':', $parts);
    }
    return $ip;
}

function checkRateLimit($config, $ip) {
    $rateFile = $config['logs']['rate_limit'];
    $maxDownloads = $config['security']['max_downloads_per_hour'];
    $currentHour = gmdate('Y-m-d-H');
    
    // Create folder if not exists
    $logDir = dirname($rateFile);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $rateData = file_exists($rateFile) ? json_decode(file_get_contents($rateFile), true) : [];
    
    // Delete old entrances
    $retentionHours = $config['retention']['rate_limit_hours'];
    $rateData = array_filter($rateData, function($entry) use ($currentHour, $retentionHours) {
        if (!isset($entry['hour'])) return false;
        $entryTime = strtotime($entry['hour'] . ':00:00');
        $currentTime = strtotime($currentHour . ':00:00');
        return ($currentTime - $entryTime) < ($retentionHours * 3600);
    });
    
    // Count the downloads of an IP per hour
    $ipCount = count(array_filter($rateData, function($entry) use ($ip, $currentHour) {
        return isset($entry['ip'], $entry['hour']) && 
               $entry['ip'] === $ip && 
               $entry['hour'] === $currentHour;
    }));
    
    if ($ipCount >= $maxDownloads) {
        return false;
    }
    
    // Add new entrance
    $rateData[] = ['ip' => $ip, 'hour' => $currentHour, 'time' => time()];
    file_put_contents($rateFile, json_encode($rateData));
    
    return true;
}

function logDownload($config, $ip, $referer) {
    $logFile = $config['logs']['downloads'];
    
    // Erstelle Verzeichnis falls nicht vorhanden
    $logDir = dirname($logFile);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $anonymizedIP = anonymizeIP($ip);
    $logEntry = gmdate('Y-m-d H:i:s') . ' UTC | ' . 
                $anonymizedIP . ' | ' . 
                'SUCCESS | ' . 
                $referer . "\n";
    
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

function logAccessDenied($config, $referer, $userAgent, $token) {
    $logFile = $config['logs']['access_denied'];
    
    // Create folder if not exists
    $logDir = dirname($logFile);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $logEntry = gmdate('Y-m-d H:i:s') . ' UTC | ' . 
                $ip . ' | ' . 
                ($referer ?: 'no-referer') . ' | ' . 
                ($userAgent ?: 'no-user-agent') . ' | ' .
                'Token: ' . substr($token, 0, 10) . '...' . "\n";
    
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}