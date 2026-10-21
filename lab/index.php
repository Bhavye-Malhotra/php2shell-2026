<?php
session_start();
if (isset($_SESSION["page"])) { include $_SESSION["page"]; }
else echo "HOME " . PHP_VERSION . "\n";
