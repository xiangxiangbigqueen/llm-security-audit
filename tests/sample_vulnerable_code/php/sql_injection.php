<?php
/**
 * 测试样本: SQL注入漏洞
 */

// 漏洞1: 直接拼接SQL语句
function vulnerable_login($username, $password) {
    $conn = mysqli_connect("localhost", "root", "", "testdb");
    // 危险: 用户输入直接拼接到SQL中
    $query = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password . "'";
    $result = mysqli_query($conn, $query);
    return mysqli_num_rows($result) > 0;
}

// 漏洞2: GET参数直接用于查询
function vulnerable_search() {
    $conn = new PDO("mysql:host=localhost;dbname=testdb", "root", "");
    $id = $_GET['id'];  // 用户输入未过滤
    $sql = "SELECT * FROM products WHERE id = " . $id;
    $stmt = $conn->query($sql);  // 危险: SQL注入
    return $stmt->fetchAll();
}

// 漏洞3: ORDER BY注入
function vulnerable_order() {
    $conn = mysqli_connect("localhost", "root", "", "testdb");
    $order = $_GET['sort'];  // 用户控制排序字段
    $query = "SELECT * FROM items ORDER BY $order";  // 危险: 注入点
    return mysqli_query($conn, $query);
}

// 漏洞4: LIKE注入
function vulnerable_like_search($keyword) {
    $conn = new PDO("mysql:host=localhost;dbname=testdb", "root", "");
    $sql = "SELECT * FROM articles WHERE title LIKE '%" . $keyword . "%'";
    return $conn->query($sql)->fetchAll();
}

// 硬编码密钥
$SECRET_KEY = "sk_live_abcdef123456789";  // 漏洞: 硬编码密钥
$DB_PASSWORD = "admin123";  // 漏洞: 硬编码数据库密码

if (isset($_GET['username'])) {
    vulnerable_login($_GET['username'], $_GET['password']);
}
?>