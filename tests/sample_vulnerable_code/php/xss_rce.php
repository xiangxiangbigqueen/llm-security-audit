<?php
/**
 * 测试样本: XSS和RCE漏洞
 */

// 漏洞1: 反射型XSS
function display_search_result() {
    $query = $_GET['q'];
    // 危险: 用户输入直接输出到HTML
    echo "<h2>搜索结果: " . $query . "</h2>";
}

// 漏洞2: 存储型XSS
function save_comment($comment) {
    $conn = new PDO("mysql:host=localhost;dbname=testdb", "root", "");
    // 未转义直接存储
    $conn->exec("INSERT INTO comments (content) VALUES ('$comment')");
}

function show_comments() {
    $conn = new PDO("mysql:host=localhost;dbname=testdb", "root", "");
    $comments = $conn->query("SELECT content FROM comments")->fetchAll();
    foreach ($comments as $c) {
        echo "<div>" . $c['content'] . "</div>";  // 危险: 存储的XSS
    }
}

// 漏洞3: 命令注入/RCE
function ping_host($host) {
    $output = shell_exec("ping -c 4 " . $host);  // 危险: RCE
    return $output;
}

// 漏洞4: 任意文件包含
function load_template($page) {
    include("templates/" . $page);  // 危险: LFI/RFI
}

// 漏洞5: 反序列化漏洞
function process_data() {
    $data = $_POST['data'];
    $obj = unserialize($data);  // 危险: 反序列化攻击
    return $obj;
}

// 漏洞6: 任意文件上传
function upload_file() {
    $target = "uploads/" . $_FILES['file']['name'];  // 未检查文件类型
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "File uploaded to: " . $target;
}

if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'search': display_search_result(); break;
        case 'ping': echo ping_host($_GET['host']); break;
        case 'page': load_template($_GET['page']); break;
    }
}
?>