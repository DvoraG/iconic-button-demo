<?php
// cleanup-logs.php - automatic clean logs using a cronjob on a daily basis

define('CONFIG_LOADED', true);
$config = require dirname(__DIR__) . '/config/demo-config.php';

// Clean downloads log
cleanupLog(
    $config['logs']['downloads'],
    $config['retention']['downloads_log']
);

// Clean access-denied log
cleanupLog(
    $config['logs']['access_denied'],
    $config['retention']['access_denied_log']
);

// Clean rate-limit data
cleanupRateLimit(
    $config['logs']['rate_limit'],
    $config['retention']['rate_limit_hours']
);

echo "Cleanup succeeded: " . gmdate('Y-m-d H:i:s') . " UTC\n";

function cleanupLog($logFile, $retentionDays) {
    if (!file_exists($logFile)) return;

    $lines = file($logFile);
    $cutoff = strtotime("-{$retentionDays} days");

    $filtered = array_filter($lines, function($line) use ($cutoff) {
        if (preg_match('/^(\d{4}-\d{2}-\d{2})/', $line, $matches)) {
            $logDate = strtotime($matches[1]);
            return $logDate > $cutoff;
        }
        return true;
    });

    file_put_contents($logFile, implode('', $filtered));
}

function cleanupRateLimit($rateFile, $retentionHours) {
    if (!file_exists($rateFile)) return;

    $data = json_decode(file_get_contents($rateFile), true);
    $cutoff = time() - ($retentionHours * 3600);

    $filtered = array_filter($data, function($entry) use ($cutoff) {
        return isset($entry['time']) && $entry['time'] > $cutoff;
    });

    file_put_contents($rateFile, json_encode(array_values($filtered)));
}