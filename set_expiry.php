<?php
// set_expiry.php
// Securely update user_expiry.json with new expiry data from the panel (AJAX POST)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['username']) || !isset($input['expiry'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

$username = trim($input['username']);
$expiry = trim($input['expiry']);
if (!$username || !$expiry) {
    http_response_code(400);
    echo json_encode(['error' => 'Empty username or expiry']);
    exit;
}

$user_expiry_path = __DIR__ . '/user_expiry.json';
$expiry_data = file_exists($user_expiry_path) ? json_decode(file_get_contents($user_expiry_path), true) : [];
if (!is_array($expiry_data)) $expiry_data = [];

// Update or add the user's expiry
$found = false;
foreach ($expiry_data as &$entry) {
    if ($entry['username'] === $username) {
        $entry['expiry'] = $expiry;
        $found = true;
        break;
    }
}
if (!$found) {
    $expiry_data[] = ['username' => $username, 'expiry' => $expiry];
}

file_put_contents($user_expiry_path, json_encode($expiry_data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
echo json_encode(['success' => true]);
