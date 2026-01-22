<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 0);

ob_start();

$AUTH_KEY = 'AKAI';
if (!isset($_GET['auth']) || $_GET['auth'] !== $AUTH_KEY) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body></body></html>';
    ob_end_flush();
    exit;
}

class ShellScanner {
    private $patterns = [
        'dangerous_functions' => [
            'eval\s*\(', 'exec\s*\(', 'system\s*\(', 'shell_exec\s*\(', 'passthru\s*\(',
            'popen\s*\(', 'proc_open\s*\(', 'pcntl_exec\s*\(', 'assert\s*\(', 'preg_replace\s*\(.*/e',
            'create_function\s*\(', 'include\s*\(', 'require\s*\(', 'include_once\s*\(', 'require_once\s*\(',
            'file_put_contents\s*\(', 'fwrite\s*\(', 'fopen\s*\(', 'curl_exec\s*\(', 'curl_multi_exec\s*\(',
            'mail\s*\(', 'putenv\s*\(', 'dl\s*\(', 'backtick\s*`', 'phpinfo\s*\(', 'chmod\s*\(', 'chown\s*\('
        ],
        
        'obfuscation_patterns' => [
            'base64_decode\s*\(', 'gzinflate\s*\(', 'gzuncompress\s*\(', 'str_rot13\s*\(',
            'rawurldecode\s*\(', 'urldecode\s*\(', 'convert_uudecode\s*\(', 'gzdecode\s*\(',
            'mcrypt_decrypt\s*\(', 'openssl_decrypt\s*\(', 'pack\s*\(.*H.*', 'hex2bin\s*\(',
            'chr\s*\(.*\.', '\$\w+\s*=\s*\$\w+\s*\.\s*\$\w+', '\$\w+\s*=\s*["\'].*["\']\s*\.\s*\$\w+'
        ],
        
        'suspicious_keywords' => [
            'wso', 'c99', 'r57', 'b374k', 'shell', 'backdoor', 'hack', 'hacker', 'defaced',
            'bypass', 'exploit', 'uploader', 'cmd', 'password', 'admin', 'root', 'cpanel',
            'symlink', 'sym', 'uname', 'id', 'whoami', 'suid', 'perl', 'python', 'nc ',
            'netcat', 'reverse', 'bind', 'shell', 'sh3ll', '0wn3d', 'h4x0r', '1337'
        ],
        
        'common_shell_patterns' => [
            '\$_POST\[', '\$_GET\[', '\$_REQUEST\[', '\$_COOKIE\[', '\$_SESSION\[',
            '\$GLOBALS\[', '\$\w+\s*=\s*\$\w+\[', 'if\s*\(\s*isset\s*\(\s*\$\_(POST|GET|REQUEST)',
            'if\s*\(\s*\$\_(POST|GET|REQUEST)\[', '@eval\s*\(', '@exec\s*\(', '@system\s*\(',
            'error_reporting\s*\(\s*0\s*\)', 'ini_set\s*\(\s*["\']display_errors["\']\s*,\s*0',
            'ob_start\s*\(\)', 'register_shutdown_function', 'set_error_handler',
            'set_time_limit\s*\(\s*0\s*\)', 'ignore_user_abort\s*\(\s*1\s*\)'
        ],
        
        'webshell_fingerprints' => [
            'r57shell', 'c99shell', 'wso shell', 'b374k shell', 'PHPShell', 'Kacak Shell',
            'Miyachung', 'Fly Shell', 'DxShell', 'Cyber Shell', 'Mini Shell', 'Simple Shell',
            'PhpSpy', 'WebAdmin', 'File Manager', 'Uploader', 'Php Backdoor', 'ASPX Shell',
            'JSP Shell', 'Perl Shell', 'Python Shell', 'Ruby Shell'
        ],
        
        'encoded_patterns' => [
            'eval\s*\(\s*base64_decode\s*\(', 'eval\s*\(\s*gzinflate\s*\(',
            'eval\s*\(\s*rawurldecode\s*\(', 'preg_replace\s*\(["\']/.*/e["\']',
            'assert\s*\(\s*base64_decode\s*\(', 'create_function\s*\(\s*["\'].*["\']\s*,\s*base64_decode',
            'call_user_func\s*\(\s*["\']base64_decode["\']', 'array_map\s*\(\s*["\']base64_decode["\']'
        ],
        
        'file_operations' => [
            'file_get_contents\s*\(\s*["\']php://input["\']', 'php://stdin', 'php://stdout',
            'php://stderr', 'php://filter', 'data://', 'expect://', 'ssh2://',
            'rar://', 'ogg://', 'zip://', 'phar://'
        ],
        
        'database_operations' => [
            'mysql_query\s*\(', 'mysqli_query\s*\(', 'pg_query\s*\(', 'sqlite_query\s*\(',
            'mssql_query\s*\(', 'oci_execute\s*\(', 'PDO::query', 'PDO::exec',
            'mysql_connect\s*\(', 'mysqli_connect\s*\(', 'new PDO\s*\('
        ],
        
        'network_operations' => [
            'fsockopen\s*\(', 'pfsockopen\s*\(', 'stream_socket_client\s*\(', 'socket_create\s*\(',
            'socket_connect\s*\(', 'stream_socket_server\s*\(', 'file_get_contents\s*\(\s*["\']http',
            'curl_init\s*\(', 'fopen\s*\(\s*["\']http', 'get_headers\s*\(', 'get_meta_tags\s*\('
        ]
    ];
    
    private $extensions = [
        'php' => ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phps'],
        'asp' => ['asp', 'aspx', 'ashx', 'asmx'],
        'jsp' => ['jsp', 'jspx', 'jspf'],
        'perl' => ['pl', 'pm', 'cgi'],
        'python' => ['py', 'pyc', 'pyo'],
        'ruby' => ['rb', 'erb'],
        'shell' => ['sh', 'bash', 'csh', 'ksh', 'zsh'],
        'other' => ['htaccess', 'htpasswd', 'inc', 'txt', 'log', 'bak', 'old', 'swp']
    ];
    
    public function scanFile($file_path, $custom_patterns = []) {
        $results = [
            'file_path' => $file_path,
            'exists' => false,
            'readable' => false,
            'is_file' => false,
            'size' => 0,
            'modified' => 0,
            'permissions' => '',
            'owner' => '',
            'group' => '',
            'content_preview' => '',
            'patterns_found' => [],
            'score' => 0,
            'danger_level' => 'safe',
            'suspicious_lines' => [],
            'analysis' => []
        ];
        
        if (!file_exists($file_path)) {
            $results['analysis'][] = 'File does not exist';
            return $results;
        }
        
        $results['exists'] = true;
        $results['is_file'] = is_file($file_path);
        $results['readable'] = is_readable($file_path);
        $results['size'] = filesize($file_path);
        $results['modified'] = filemtime($file_path);
        $results['permissions'] = substr(sprintf('%o', fileperms($file_path)), -4);
        
        if (function_exists('posix_getpwuid')) {
            $owner_info = @posix_getpwuid(fileowner($file_path));
            $results['owner'] = $owner_info ? $owner_info['name'] : fileowner($file_path);
        } else {
            $results['owner'] = fileowner($file_path);
        }
        
        if (!$results['readable'] || $results['size'] > 10485760) { // 10MB limit
            $results['analysis'][] = 'File too large or not readable';
            return $results;
        }
        
        $content = @file_get_contents($file_path);
        if ($content === false) {
            $results['analysis'][] = 'Cannot read file content';
            return $results;
        }
        
        // Get first 500 chars for preview
        $results['content_preview'] = substr($content, 0, 500);
        
        // Combine all patterns
        $all_patterns = array_merge(
            $this->patterns['dangerous_functions'],
            $this->patterns['obfuscation_patterns'],
            $this->patterns['suspicious_keywords'],
            $this->patterns['common_shell_patterns'],
            $this->patterns['webshell_fingerprints'],
            $this->patterns['encoded_patterns'],
            $this->patterns['file_operations'],
            $this->patterns['database_operations'],
            $this->patterns['network_operations'],
            $custom_patterns
        );
        
        $score = 0;
        $found_patterns = [];
        $suspicious_lines = [];
        
        // Split content into lines for line-by-line analysis
        $lines = explode("\n", $content);
        $line_number = 0;
        
        foreach ($lines as $line) {
            $line_number++;
            $line = trim($line);
            
            if (empty($line)) continue;
            
            foreach ($all_patterns as $pattern) {
                if (preg_match('/' . $pattern . '/i', $line)) {
                    $found_patterns[$pattern][] = $line_number;
                    
                    // Calculate score based on pattern type
                    if (in_array($pattern, $this->patterns['dangerous_functions'])) {
                        $score += 10;
                    } elseif (in_array($pattern, $this->patterns['encoded_patterns'])) {
                        $score += 15;
                    } elseif (in_array($pattern, $this->patterns['webshell_fingerprints'])) {
                        $score += 20;
                    } else {
                        $score += 5;
                    }
                    
                    $suspicious_lines[$line_number] = [
                        'line' => $line,
                        'pattern' => $pattern
                    ];
                }
            }
            
            // Check for specific shell signatures
            $this->checkSpecificSignatures($line, $score, $suspicious_lines, $line_number);
        }
        
        // Check for file type
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $is_script = false;
        
        foreach ($this->extensions as $type => $exts) {
            if (in_array($extension, $exts)) {
                $is_script = true;
                if ($type == 'php' || $type == 'asp' || $type == 'jsp') {
                    $score += 5; // Web script files get extra score
                }
                break;
            }
        }
        
        // Check for suspicious file names
        $filename = basename($file_path);
        if (preg_match('/(shell|backdoor|cmd|wso|c99|r57|b374k|upload|admin|hack)/i', $filename)) {
            $score += 15;
            $results['analysis'][] = 'Suspicious filename detected';
        }
        
        // Check for hidden files
        if (substr($filename, 0, 1) === '.') {
            $score += 10;
            $results['analysis'][] = 'Hidden file detected';
        }
        
        // Check for permissions
        if (is_executable($file_path)) {
            $score += 5;
            $results['analysis'][] = 'File is executable';
        }
        
        // Check for recent modification
        $one_week_ago = time() - (7 * 24 * 60 * 60);
        if ($results['modified'] > $one_week_ago) {
            $score += 3;
            $results['analysis'][] = 'Recently modified';
        }
        
        // Determine danger level
        if ($score >= 50) {
            $danger_level = 'CRITICAL';
        } elseif ($score >= 30) {
            $danger_level = 'HIGH';
        } elseif ($score >= 15) {
            $danger_level = 'MEDIUM';
        } elseif ($score >= 5) {
            $danger_level = 'LOW';
        } else {
            $danger_level = 'SAFE';
        }
        
        $results['patterns_found'] = $found_patterns;
        $results['score'] = $score;
        $results['danger_level'] = $danger_level;
        $results['suspicious_lines'] = $suspicious_lines;
        
        // Generate analysis summary
        if ($score > 0) {
            $results['analysis'][] = "Found " . count($found_patterns) . " suspicious patterns";
            $results['analysis'][] = "Total score: $score";
            $results['analysis'][] = "Danger level: $danger_level";
        } else {
            $results['analysis'][] = "No suspicious patterns found";
        }
        
        return $results;
    }
    
    public function scanDirectory($directory, $recursive = true, $custom_patterns = []) {
        $results = [
            'directory' => $directory,
            'exists' => false,
            'readable' => false,
            'total_files' => 0,
            'scanned_files' => 0,
            'suspicious_files' => [],
            'critical_files' => [],
            'scan_time' => 0,
            'summary' => []
        ];
        
        if (!file_exists($directory)) {
            $results['summary'][] = "Directory does not exist: $directory";
            return $results;
        }
        
        if (!is_dir($directory)) {
            $results['summary'][] = "Path is not a directory: $directory";
            return $results;
        }
        
        if (!is_readable($directory)) {
            $results['summary'][] = "Directory is not readable: $directory";
            return $results;
        }
        
        $results['exists'] = true;
        $results['readable'] = true;
        
        $start_time = microtime(true);
        $files = $this->getDirectoryFiles($directory, $recursive);
        $results['total_files'] = count($files);
        
        $suspicious_count = 0;
        $critical_count = 0;
        
        foreach ($files as $file) {
            $file_results = $this->scanFile($file, $custom_patterns);
            $results['scanned_files']++;
            
            if ($file_results['score'] > 0) {
                $results['suspicious_files'][$file] = $file_results;
                
                if ($file_results['danger_level'] == 'CRITICAL' || $file_results['danger_level'] == 'HIGH') {
                    $results['critical_files'][$file] = $file_results;
                    $critical_count++;
                }
                
                $suspicious_count++;
            }
            
            // Limit scanning for performance
            if ($results['scanned_files'] >= 1000) {
                $results['summary'][] = "Stopped scanning after 1000 files (performance limit)";
                break;
            }
        }
        
        $end_time = microtime(true);
        $results['scan_time'] = round($end_time - $start_time, 2);
        
        // Generate summary
        $results['summary'][] = "Scanned directory: $directory";
        $results['summary'][] = "Total files found: " . $results['total_files'];
        $results['summary'][] = "Files scanned: " . $results['scanned_files'];
        $results['summary'][] = "Suspicious files: $suspicious_count";
        $results['summary'][] = "Critical files: $critical_count";
        $results['summary'][] = "Scan time: " . $results['scan_time'] . " seconds";
        
        return $results;
    }
    
    private function getDirectoryFiles($directory, $recursive = true) {
        $files = [];
        
        if (!is_dir($directory) || !is_readable($directory)) {
            return $files;
        }
        
        $items = @scandir($directory);
        if ($items === false) {
            return $files;
        }
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            
            $full_path = $directory . '/' . $item;
            
            if (is_dir($full_path) && $recursive) {
                // Skip some system directories
                $skip_dirs = ['proc', 'sys', 'dev', 'run', 'tmp'];
                if (in_array($item, $skip_dirs)) continue;
                
                $sub_files = $this->getDirectoryFiles($full_path, $recursive);
                $files = array_merge($files, $sub_files);
            } elseif (is_file($full_path)) {
                // Check file extension
                $extension = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
                $valid_extensions = array_merge(
                    $this->extensions['php'],
                    $this->extensions['asp'],
                    $this->extensions['jsp'],
                    $this->extensions['perl'],
                    $this->extensions['python'],
                    $this->extensions['ruby'],
                    $this->extensions['shell'],
                    $this->extensions['other']
                );
                
                if (in_array($extension, $valid_extensions)) {
                    $files[] = $full_path;
                }
            }
        }
        
        return $files;
    }
    
    private function checkSpecificSignatures($line, &$score, &$suspicious_lines, $line_number) {
        // Check for specific shell signatures
        $signatures = [
            // Common shell signatures
            '/\$\w+\s*=\s*\$_POST\[\s*[\'"]\w+[\'"]\s*\]\s*;/' => 15,
            '/eval\s*\(\s*base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]+[\'"]\s*\)\s*\)/' => 25,
            '/@\$\w+\s*=\s*\$\w+\s*\(\s*\$\w+\[/' => 20,
            '/passthru\s*\(\s*[\'"]id[\'"]\s*\)/' => 30,
            '/system\s*\(\s*[\'"]wget[\'"]/' => 25,
            '/shell_exec\s*\(\s*[\'"]curl[\'"]/' => 25,
            '/preg_replace\s*\(["\']\/\.\*\/e["\']/' => 30,
            
            // WSO shell signatures
            '/if\s*\(\s*isset\s*\(\s*\$_POST\[\s*[\'"]pass[\'"]/' => 20,
            '/WSO\s*\(version\s*2/' => 30,
            '/c99shell/' => 30,
            '/r57shell/' => 30,
            '/b374k\s*shell/' => 30,
            
            // Obfuscated code patterns
            '/\$\w+\s*=\s*["\'][a-zA-Z0-9+\/=]{100,}["\']/' => 20,
            '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{50,}[\'"]/' => 15,
            '/gzinflate\s*\(\s*base64_decode/' => 25,
            
            // Backdoor upload patterns
            '/move_uploaded_file\s*\(\s*\$_FILES/' => 15,
            '/copy\s*\(\s*\$_FILES\[/' => 15,
            '/file_put_contents\s*\(\s*[\'"]\w+\.php[\'"]/' => 20,
            
            // Mailer shells
            '/mail\s*\(\s*[\'"]\w+@[\w\.]+[\'"]/' => 10,
            '/phpmailer/i' => 10,
        ];
        
        foreach ($signatures as $pattern => $pattern_score) {
            if (preg_match($pattern, $line)) {
                $score += $pattern_score;
                $suspicious_lines[$line_number] = [
                    'line' => $line,
                    'pattern' => 'Specific Signature: ' . substr($pattern, 0, 50)
                ];
            }
        }
    }
    
    public function searchInContent($content, $search_patterns) {
        $results = [
            'total_matches' => 0,
            'matches' => [],
            'lines_with_matches' => []
        ];
        
        if (empty($content) || empty($search_patterns)) {
            return $results;
        }
        
        $lines = explode("\n", $content);
        $line_number = 0;
        
        foreach ($lines as $line) {
            $line_number++;
            
            foreach ($search_patterns as $pattern) {
                if (empty(trim($pattern))) continue;
                
                if (strpos($line, $pattern) !== false) {
                    $results['total_matches']++;
                    $results['matches'][$pattern][] = $line_number;
                    $results['lines_with_matches'][$line_number] = [
                        'line' => $line,
                        'pattern' => $pattern
                    ];
                }
                
                // Also try regex if pattern looks like regex
                if (strpos($pattern, '/') === 0 && substr($pattern, -1) === '/') {
                    if (preg_match($pattern, $line)) {
                        $results['total_matches']++;
                        $results['matches'][$pattern][] = $line_number;
                        $results['lines_with_matches'][$line_number] = [
                            'line' => $line,
                            'pattern' => $pattern
                        ];
                    }
                }
            }
        }
        
        return $results;
    }
}

$scanner = new ShellScanner();
$scan_results = null;
$directory_results = null;
$search_results = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'scan_file' && isset($_POST['file_path'])) {
            $file_path = $_POST['file_path'];
            $custom_patterns = isset($_POST['custom_patterns']) ? 
                array_filter(array_map('trim', explode("\n", $_POST['custom_patterns']))) : [];
            
            $scan_results = $scanner->scanFile($file_path, $custom_patterns);
        }
        elseif ($_POST['action'] == 'scan_directory' && isset($_POST['directory_path'])) {
            $directory_path = $_POST['directory_path'];
            $recursive = isset($_POST['recursive']) && $_POST['recursive'] == '1';
            $custom_patterns = isset($_POST['custom_patterns']) ? 
                array_filter(array_map('trim', explode("\n", $_POST['custom_patterns']))) : [];
            
            $directory_results = $scanner->scanDirectory($directory_path, $recursive, $custom_patterns);
        }
        elseif ($_POST['action'] == 'search_content' && isset($_POST['search_path']) && isset($_POST['search_patterns'])) {
            $search_path = $_POST['search_path'];
            $search_patterns = array_filter(array_map('trim', explode("\n", $_POST['search_patterns'])));
            
            if (file_exists($search_path) && is_readable($search_path)) {
                $content = @file_get_contents($search_path);
                if ($content !== false) {
                    $search_results = $scanner->searchInContent($content, $search_patterns);
                    $search_results['file_path'] = $search_path;
                    $search_results['file_size'] = filesize($search_path);
                }
            }
        }
    }
}

ob_clean();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>◈ Advanced Shell Scanner</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #121218;
            --bg-tertiary: #1a1a24;
            --bg-card: #151520;
            --text-primary: #e0e0ff;
            --text-secondary: #a0a0c0;
            --text-muted: #707090;
            --accent-red: #ff2e63;
            --accent-red-dark: #d91e4f;
            --accent-blue: #4a6fff;
            --accent-green: #08d9a6;
            --accent-yellow: #ffb347;
            --accent-purple: #9d4edd;
            --border-color: #2a2a3a;
            --border-light: #3a3a4a;
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.5);
            --gradient-red: linear-gradient(135deg, #ff2e63 0%, #d91e4f 100%);
            --gradient-blue: linear-gradient(135deg, #4a6fff 0%, #2a4fcc 100%);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 24px 32px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gradient-red);
        }
        
        .logo-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 28px;
            background: var(--gradient-red);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        
        .server-status {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .scan-types {
            display: flex;
            gap: 4px;
            margin-bottom: 24px;
            background: var(--bg-tertiary);
            padding: 8px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
        }
        
        .scan-btn {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            padding: 10px 20px;
            background: transparent;
            border: none;
            border-radius: 8px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .scan-btn:hover {
            background: rgba(255, 46, 99, 0.1);
            color: var(--accent-red);
        }
        
        .scan-btn.active {
            background: var(--gradient-red);
            color: white;
            box-shadow: var(--shadow-sm);
        }
        
        .scan-section {
            display: none;
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--shadow-md);
            border: 1px solid var(--border-color);
        }
        
        .scan-section.active {
            display: block;
            animation: slideIn 0.2s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section-title {
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 18px;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 16px;
            background: var(--accent-red);
            border-radius: 2px;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            font-size: 13px;
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        
        .form-control {
            font-family: 'JetBrains Mono', monospace;
            width: 100%;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 13px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--accent-red);
            box-shadow: 0 0 0 2px rgba(255, 46, 99, 0.1);
        }
        
        textarea.form-control {
            min-height: 150px;
            resize: vertical;
        }
        
        .btn {
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }
        
        .btn-primary {
            background: var(--gradient-blue);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-danger {
            background: var(--gradient-red);
            color: white;
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #08d9a6 0%, #06b893 100%);
            color: white;
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, #ffb347 0%, #ff9a3d 100%);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .alert {
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 20px;
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            border: 1px solid transparent;
        }
        
        .alert-success {
            background: rgba(8, 217, 166, 0.1);
            border-color: var(--accent-green);
            color: var(--accent-green);
        }
        
        .alert-danger {
            background: rgba(255, 46, 99, 0.1);
            border-color: var(--accent-red);
            color: var(--accent-red);
        }
        
        .alert-info {
            background: rgba(74, 111, 255, 0.1);
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }
        
        .alert-warning {
            background: rgba(255, 179, 71, 0.1);
            border-color: var(--accent-yellow);
            color: var(--accent-yellow);
        }
        
        .results-container {
            margin-top: 20px;
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 16px;
            border: 1px solid var(--border-color);
        }
        
        .result-item {
            padding: 12px;
            margin-bottom: 8px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            border-left: 4px solid var(--accent-green);
        }
        
        .result-item.warning {
            border-left-color: var(--accent-yellow);
        }
        
        .result-item.danger {
            border-left-color: var(--accent-red);
        }
        
        .result-item.critical {
            border-left-color: #ff0000;
            border-left-width: 6px;
            background: rgba(255, 0, 0, 0.1);
        }
        
        .danger-level {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .level-safe {
            background: rgba(8, 217, 166, 0.2);
            color: var(--accent-green);
            border: 1px solid rgba(8, 217, 166, 0.3);
        }
        
        .level-low {
            background: rgba(255, 179, 71, 0.2);
            color: var(--accent-yellow);
            border: 1px solid rgba(255, 179, 71, 0.3);
        }
        
        .level-medium {
            background: rgba(255, 179, 71, 0.3);
            color: var(--accent-yellow);
            border: 1px solid rgba(255, 179, 71, 0.5);
        }
        
        .level-high {
            background: rgba(255, 46, 99, 0.3);
            color: var(--accent-red);
            border: 1px solid rgba(255, 46, 99, 0.5);
        }
        
        .level-critical {
            background: rgba(255, 0, 0, 0.3);
            color: #ff0000;
            border: 1px solid rgba(255, 0, 0, 0.5);
        }
        
        .file-info {
            background: var(--bg-card);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border: 1px solid var(--border-color);
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 10px;
        }
        
        .info-item {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        
        .info-label {
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .info-value {
            color: var(--text-primary);
            word-break: break-all;
        }
        
        .pattern-list {
            max-height: 300px;
            overflow-y: auto;
            background: var(--bg-primary);
            border-radius: 6px;
            padding: 10px;
            border: 1px solid var(--border-color);
        }
        
        .pattern-item {
            padding: 8px;
            margin-bottom: 5px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            border-left: 3px solid var(--accent-blue);
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            word-break: break-all;
        }
        
        .line-number {
            color: var(--accent-yellow);
            font-weight: bold;
        }
        
        .suspicious-line {
            background: rgba(255, 46, 99, 0.1);
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
            border-left: 3px solid var(--accent-red);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
        }
        
        .stat-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-green);
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .file-list {
            max-height: 400px;
            overflow-y: auto;
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 10px;
            border: 1px solid var(--border-color);
        }
        
        .file-list-item {
            padding: 10px;
            margin-bottom: 5px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            border-left: 4px solid var(--accent-blue);
        }
        
        .file-list-item:hover {
            background: rgba(74, 111, 255, 0.1);
            transform: translateX(5px);
        }
        
        .file-list-item.critical {
            border-left-color: #ff0000;
            background: rgba(255, 0, 0, 0.1);
        }
        
        .file-list-item.high {
            border-left-color: var(--accent-red);
            background: rgba(255, 46, 99, 0.1);
        }
        
        .file-name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-primary);
            word-break: break-all;
        }
        
        .file-score {
            float: right;
            font-weight: bold;
            color: var(--accent-yellow);
        }
        
        .preview-container {
            background: #000;
            color: #0f0;
            font-family: 'JetBrains Mono', monospace;
            padding: 15px;
            border-radius: 8px;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 10px;
            border: 1px solid var(--border-color);
        }
        
        .pattern-help {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            border: 1px solid var(--border-color);
        }
        
        .help-title {
            font-weight: bold;
            color: var(--accent-blue);
            margin-bottom: 10px;
        }
        
        .help-list {
            list-style: none;
            padding-left: 0;
        }
        
        .help-list li {
            padding: 5px 0;
            font-size: 12px;
            color: var(--text-secondary);
            border-bottom: 1px dashed var(--border-light);
        }
        
        .help-list li:last-child {
            border-bottom: none;
        }
        
        .pattern-example {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-yellow);
            background: rgba(255, 179, 71, 0.1);
            padding: 3px 6px;
            border-radius: 3px;
            margin: 0 5px;
            font-size: 11px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header {
                padding: 15px;
            }
            
            .scan-types {
                flex-direction: column;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-container">
                <div class="logo"><i class="fas fa-shield-alt"></i> Advanced Shell Scanner</div>
                <div class="server-status">
                    <div class="status-indicator"></div>
                    <span style="color: var(--accent-green); font-family: 'JetBrains Mono', monospace;">READY</span>
                </div>
            </div>
            
            <div class="scan-types">
                <button class="scan-btn active" data-section="file-scan">
                    <i class="fas fa-file-code"></i> File Scan
                </button>
                <button class="scan-btn" data-section="directory-scan">
                    <i class="fas fa-folder"></i> Directory Scan
                </button>
                <button class="scan-btn" data-section="content-search">
                    <i class="fas fa-search"></i> Content Search
                </button>
                <button class="scan-btn" data-section="patterns">
                    <i class="fas fa-list"></i> Pattern Library
                </button>
            </div>
        </header>
        
        <section id="file-scan" class="scan-section active">
            <h2 class="section-title"><i class="fas fa-file-code"></i> Single File Scanner</h2>
            
            <form method="POST">
                <input type="hidden" name="action" value="scan_file">
                
                <div class="form-group">
                    <label class="form-label">File Path to Scan</label>
                    <input type="text" name="file_path" class="form-control" 
                           value="<?= isset($_POST['file_path']) ? htmlspecialchars($_POST['file_path']) : '' ?>"
                           placeholder="/path/to/file.php" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Custom Search Patterns (one per line)</label>
                    <textarea name="custom_patterns" class="form-control" 
                              placeholder="Example: eval\(
base64_decode
shell_exec
wso
c99"><?= isset($_POST['custom_patterns']) ? htmlspecialchars($_POST['custom_patterns']) : '' ?></textarea>
                </div>
                
                <button type="submit" class="btn btn-danger">
                    <i class="fas fa-search"></i> Scan File
                </button>
            </form>
            
            <?php if ($scan_results): ?>
            <div class="results-container">
                <h3 class="section-title" style="font-size: 16px;">Scan Results</h3>
                
                <div class="file-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">File Path</div>
                            <div class="info-value"><?= htmlspecialchars($scan_results['file_path']) ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">File Size</div>
                            <div class="info-value"><?= number_format($scan_results['size']) ?> bytes</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Permissions</div>
                            <div class="info-value"><?= htmlspecialchars($scan_results['permissions']) ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Owner</div>
                            <div class="info-value"><?= htmlspecialchars($scan_results['owner']) ?></div>
                        </div>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value"><?= $scan_results['score'] ?></div>
                            <div class="stat-label">Risk Score</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">
                                <span class="danger-level level-<?= strtolower($scan_results['danger_level']) ?>">
                                    <?= $scan_results['danger_level'] ?>
                                </span>
                            </div>
                            <div class="stat-label">Danger Level</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?= count($scan_results['patterns_found']) ?></div>
                            <div class="stat-label">Patterns Found</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?= count($scan_results['suspicious_lines']) ?></div>
                            <div class="stat-label">Suspicious Lines</div>
                        </div>
                    </div>
                    
                    <?php if (!empty($scan_results['analysis'])): ?>
                    <div class="alert alert-<?= $scan_results['danger_level'] == 'SAFE' ? 'success' : ($scan_results['danger_level'] == 'LOW' ? 'warning' : 'danger') ?>">
                        <?php foreach ($scan_results['analysis'] as $analysis): ?>
                        <div><?= htmlspecialchars($analysis) ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                </div>
                
                <?php if (!empty($scan_results['patterns_found'])): ?>
                <div class="form-group">
                    <label class="form-label">Patterns Found (<?= count($scan_results['patterns_found']) ?> patterns)</label>
                    <div class="pattern-list">
                        <?php foreach ($scan_results['patterns_found'] as $pattern => $lines): ?>
                        <div class="pattern-item">
                            <strong><?= htmlspecialchars($pattern) ?></strong>
                            <br>
                            <span class="line-number">Lines: <?= implode(', ', $lines) ?></span>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (!empty($scan_results['suspicious_lines'])): ?>
                <div class="form-group">
                    <label class="form-label">Suspicious Lines (<?= count($scan_results['suspicious_lines']) ?> lines)</label>
                    <div class="pattern-list">
                        <?php foreach ($scan_results['suspicious_lines'] as $line_num => $line_info): ?>
                        <div class="suspicious-line">
                            <span class="line-number">Line <?= $line_num ?>:</span>
                            <br>
                            <code><?= htmlspecialchars($line_info['line']) ?></code>
                            <br>
                            <small>Pattern: <?= htmlspecialchars($line_info['pattern']) ?></small>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (!empty($scan_results['content_preview'])): ?>
                <div class="form-group">
                    <label class="form-label">Content Preview (first 500 characters)</label>
                    <div class="preview-container">
                        <?= htmlspecialchars($scan_results['content_preview']) ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </section>
        
        <section id="directory-scan" class="scan-section">
            <h2 class="section-title"><i class="fas fa-folder"></i> Directory Scanner</h2>
            
            <form method="POST">
                <input type="hidden" name="action" value="scan_directory">
                
                <div class="form-group">
                    <label class="form-label">Directory Path to Scan</label>
                    <input type="text" name="directory_path" class="form-control" 
                           value="<?= isset($_POST['directory_path']) ? htmlspecialchars($_POST['directory_path']) : '/' ?>"
                           placeholder="/path/to/directory" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <input type="checkbox" name="recursive" value="1" checked> 
                        Scan recursively (all subdirectories)
                    </label>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Custom Search Patterns (one per line)</label>
                    <textarea name="custom_patterns" class="form-control" 
                              placeholder="Add custom patterns to search for..."><?= isset($_POST['custom_patterns']) ? htmlspecialchars($_POST['custom_patterns']) : '' ?></textarea>
                </div>
                
                <button type="submit" class="btn btn-danger">
                    <i class="fas fa-search"></i> Scan Directory
                </button>
            </form>
            
            <?php if ($directory_results): ?>
            <div class="results-container">
                <h3 class="section-title" style="font-size: 16px;">Directory Scan Results</h3>
                
                <div class="file-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">Directory</div>
                            <div class="info-value"><?= htmlspecialchars($directory_results['directory']) ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Total Files Found</div>
                            <div class="info-value"><?= $directory_results['total_files'] ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Files Scanned</div>
                            <div class="info-value"><?= $directory_results['scanned_files'] ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Scan Time</div>
                            <div class="info-value"><?= $directory_results['scan_time'] ?> seconds</div>
                        </div>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value"><?= count($directory_results['suspicious_files']) ?></div>
                            <div class="stat-label">Suspicious Files</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?= count($directory_results['critical_files']) ?></div>
                            <div class="stat-label">Critical Files</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?= $directory_results['total_files'] - count($directory_results['suspicious_files']) ?></div>
                            <div class="stat-label">Clean Files</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value"><?= $directory_results['scanned_files'] ?></div>
                            <div class="stat-label">Files Checked</div>
                        </div>
                    </div>
                    
                    <?php if (!empty($directory_results['summary'])): ?>
                    <div class="alert alert-info">
                        <?php foreach ($directory_results['summary'] as $summary): ?>
                        <div><?= htmlspecialchars($summary) ?></div>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                </div>
                
                <?php if (!empty($directory_results['critical_files'])): ?>
                <div class="form-group">
                    <label class="form-label">Critical Files Found (<?= count($directory_results['critical_files']) ?> files)</label>
                    <div class="file-list">
                        <?php foreach ($directory_results['critical_files'] as $file_path => $file_results): ?>
                        <div class="file-list-item critical" onclick="showFileDetails('<?= base64_encode($file_path) ?>')">
                            <div class="file-name">
                                <?= htmlspecialchars(basename($file_path)) ?>
                                <div class="file-score">Score: <?= $file_results['score'] ?></div>
                            </div>
                            <small style="color: var(--text-muted);"><?= htmlspecialchars(dirname($file_path)) ?></small>
                            <div>
                                <span class="danger-level level-<?= strtolower($file_results['danger_level']) ?>">
                                    <?= $file_results['danger_level'] ?>
                                </span>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (!empty($directory_results['suspicious_files']) && empty($directory_results['critical_files'])): ?>
                <div class="form-group">
                    <label class="form-label">Suspicious Files Found (<?= count($directory_results['suspicious_files']) ?> files)</label>
                    <div class="file-list">
                        <?php foreach ($directory_results['suspicious_files'] as $file_path => $file_results): ?>
                        <div class="file-list-item <?= $file_results['danger_level'] == 'HIGH' ? 'high' : '' ?>" 
                             onclick="showFileDetails('<?= base64_encode($file_path) ?>')">
                            <div class="file-name">
                                <?= htmlspecialchars(basename($file_path)) ?>
                                <div class="file-score">Score: <?= $file_results['score'] ?></div>
                            </div>
                            <small style="color: var(--text-muted);"><?= htmlspecialchars(dirname($file_path)) ?></small>
                            <div>
                                <span class="danger-level level-<?= strtolower($file_results['danger_level']) ?>">
                                    <?= $file_results['danger_level'] ?>
                                </span>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (empty($directory_results['suspicious_files'])): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> No suspicious files found in the scanned directory.
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </section>
        
        <section id="content-search" class="scan-section">
            <h2 class="section-title"><i class="fas fa-search"></i> Content Search</h2>
            
            <form method="POST">
                <input type="hidden" name="action" value="search_content">
                
                <div class="form-group">
                    <label class="form-label">File Path to Search</label>
                    <input type="text" name="search_path" class="form-control" 
                           value="<?= isset($_POST['search_path']) ? htmlspecialchars($_POST['search_path']) : '' ?>"
                           placeholder="/path/to/file.php" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Search Patterns (one per line)</label>
                    <textarea name="search_patterns" class="form-control" rows="10" 
                              placeholder="Enter patterns to search for in the file content...
Example:
eval\(
base64_decode
shell_exec
wso
c99
r57
/admin/
/password/
/^<\?php/
" required><?= isset($_POST['search_patterns']) ? htmlspecialchars($_POST['search_patterns']) : '' ?></textarea>
                </div>
                
                <button type="submit" class="btn btn-danger">
                    <i class="fas fa-search"></i> Search Content
                </button>
            </form>
            
            <?php if ($search_results): ?>
            <div class="results-container">
                <h3 class="section-title" style="font-size: 16px;">Search Results</h3>
                
                <div class="file-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">File Path</div>
                            <div class="info-value"><?= htmlspecialchars($search_results['file_path']) ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">File Size</div>
                            <div class="info-value"><?= number_format($search_results['file_size']) ?> bytes</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Total Matches</div>
                            <div class="info-value"><?= $search_results['total_matches'] ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Unique Patterns</div>
                            <div class="info-value"><?= count($search_results['matches']) ?></div>
                        </div>
                    </div>
                </div>
                
                <?php if ($search_results['total_matches'] > 0): ?>
                <div class="form-group">
                    <label class="form-label">Matches Found (<?= $search_results['total_matches'] ?> matches)</label>
                    <div class="pattern-list">
                        <?php foreach ($search_results['matches'] as $pattern => $lines): ?>
                        <div class="pattern-item">
                            <strong>Pattern: <?= htmlspecialchars($pattern) ?></strong>
                            <br>
                            <span class="line-number">Found on lines: <?= implode(', ', $lines) ?></span>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Lines with Matches</label>
                    <div class="pattern-list">
                        <?php foreach ($search_results['lines_with_matches'] as $line_num => $line_info): ?>
                        <div class="suspicious-line">
                            <span class="line-number">Line <?= $line_num ?>:</span>
                            <br>
                            <code><?= htmlspecialchars($line_info['line']) ?></code>
                            <br>
                            <small>Pattern: <?= htmlspecialchars($line_info['pattern']) ?></small>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php else: ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> No matches found for the specified patterns.
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </section>
        
        <section id="patterns" class="scan-section">
            <h2 class="section-title"><i class="fas fa-list"></i> Pattern Library</h2>
            
            <div class="pattern-help">
                <div class="help-title">Common Shell/Backdoor Patterns</div>
                <ul class="help-list">
                    <li><strong>Dangerous Functions:</strong> 
                        <span class="pattern-example">eval(</span>,
                        <span class="pattern-example">exec(</span>,
                        <span class="pattern-example">system(</span>,
                        <span class="pattern-example">shell_exec(</span>
                    </li>
                    <li><strong>Obfuscation Patterns:</strong> 
                        <span class="pattern-example">base64_decode(</span>,
                        <span class="pattern-example">gzinflate(</span>,
                        <span class="pattern-example">str_rot13(</span>
                    </li>
                    <li><strong>Common Shell Keywords:</strong> 
                        <span class="pattern-example">wso</span>,
                        <span class="pattern-example">c99</span>,
                        <span class="pattern-example">r57</span>,
                        <span class="pattern-example">b374k</span>
                    </li>
                    <li><strong>Web Input Patterns:</strong> 
                        <span class="pattern-example">$_POST[</span>,
                        <span class="pattern-example">$_GET[</span>,
                        <span class="pattern-example">$_REQUEST[</span>
                    </li>
                    <li><strong>Encoded Patterns:</strong> 
                        <span class="pattern-example">eval(base64_decode(</span>,
                        <span class="pattern-example">gzinflate(base64_decode(</span>
                    </li>
                    <li><strong>File Operations:</strong> 
                        <span class="pattern-example">file_get_contents('php://input')</span>,
                        <span class="pattern-example">move_uploaded_file(</span>
                    </li>
                    <li><strong>Network Operations:</strong> 
                        <span class="pattern-example">fsockopen(</span>,
                        <span class="pattern-example">curl_init(</span>
                    </li>
                </ul>
            </div>
            
            <div class="pattern-help">
                <div class="help-title">Regular Expression Examples</div>
                <ul class="help-list">
                    <li><span class="pattern-example">/eval\s*\(/i</span> - Find eval() calls</li>
                    <li><span class="pattern-example">/base64_decode\s*\(/i</span> - Find base64_decode() calls</li>
                    <li><span class="pattern-example">/\$_POST\[['"]\w+['"]\]/</span> - Find $_POST variable access</li>
                    <li><span class="pattern-example">/shell|backdoor|cmd|wso|c99/i</span> - Find shell keywords</li>
                    <li><span class="pattern-example">/<\?php.*\?>/s</span> - Find PHP code blocks</li>
                    <li><span class="pattern-example">/^#!\/bin\/(bash|sh)/</span> - Find shell script shebangs</li>
                </ul>
            </div>
            
            <div class="pattern-help">
                <div class="help-title">File Extensions to Scan</div>
                <ul class="help-list">
                    <li><strong>PHP:</strong> .php, .php3, .php4, .php5, .php7, .phtml</li>
                    <li><strong>ASP:</strong> .asp, .aspx, .ashx</li>
                    <li><strong>JSP:</strong> .jsp, .jspx</li>
                    <li><strong>Scripts:</strong> .pl, .py, .rb, .sh, .bash</li>
                    <li><strong>Other:</strong> .htaccess, .inc, .txt, .log, .bak</li>
                </ul>
            </div>
            
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> 
                <strong>Usage Tips:</strong><br>
                1. Use absolute paths for scanning<br>
                2. Add custom patterns to detect specific malware<br>
                3. Check hidden files (starting with .)<br>
                4. Look for recently modified files<br>
                5. Check file permissions (777, 755, etc.)
            </div>
        </section>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.scan-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    document.querySelectorAll('.scan-btn').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.scan-section').forEach(s => s.classList.remove('active'));
                    
                    btn.classList.add('active');
                    document.getElementById(btn.dataset.section).classList.add('active');
                });
            });
            
            // Auto-focus on first input
            setTimeout(() => {
                const inputs = document.querySelectorAll('input[type="text"], textarea');
                if (inputs.length > 0) {
                    inputs[0].focus();
                }
            }, 100);
        });
        
        function showFileDetails(encodedPath) {
            const filePath = atob(encodedPath);
            if (confirm('Scan this file individually?\n\n' + filePath)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';
                
                const inputAction = document.createElement('input');
                inputAction.type = 'hidden';
                inputAction.name = 'action';
                inputAction.value = 'scan_file';
                form.appendChild(inputAction);
                
                const inputPath = document.createElement('input');
                inputPath.type = 'hidden';
                inputPath.name = 'file_path';
                inputPath.value = filePath;
                form.appendChild(inputPath);
                
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
<?php ob_end_flush(); ?>
