<?php
// index.php - front door of the CMS lab fixture.
session_start();
echo "CMS-LAB PHP " . phpversion() . " PHPSESSID=" . (isset($_COOKIE['PHPSESSID']) ? $_COOKIE['PHPSESSID'] : '<none>') . "\n";
