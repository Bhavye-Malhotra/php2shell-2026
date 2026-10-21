<?php
// wp-content.php - LFI sink for the Wiz-style CMS fixture.
// Shaped after CMS template-inclusion patterns: include $_GET['page'] without
// path validation. Deliberate vulnerability for lab use; do not deploy.
session_start();
$page = isset($_GET['page']) ? $_GET['page'] : null;
if ($page !== null) {
    include $page;
}
echo "\n--- end of include ---\n";
