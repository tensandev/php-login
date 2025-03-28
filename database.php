<?php

// データベース接続情報
const DB_HOST = 'localhost:3306';
const DB_NAME = 'db_name';
const DB_USER = 'root';
const DB_PASS = 'password';

static $pdo = null;
if ($pdo === null) {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); // プリペアドステートメントをネイティブに利用
    } catch (PDOException $e) {
        die("データベース接続エラー: " . $e->getMessage());
    }
}
