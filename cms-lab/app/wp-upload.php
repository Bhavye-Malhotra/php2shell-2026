<?php
// wp-upload.php - CMS-style upload form (default PHP session.upload_progress=On).
// Accepts multipart file POSTs and stores each file.
// Deliberate lab fixture: emulates the shape of a CMS upload endpoint.
session_start();
echo "wp-upload/" . phpversion() . " ready\n";
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $out = [];
    foreach ($_FILES as $key => $meta) {
        $out[$key] = $meta['name'];
    }
    echo "FILES: " . json_encode($out) . "\n";
}
