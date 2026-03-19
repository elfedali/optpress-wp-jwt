<?php
/**
 * Plugin Name: OptPress JWT
 * Description: Enhanced JWT Authentication plugin for WordPress with mobile app support, featuring rate limiting, session management, and comprehensive security
 * Version: 1.2.0
 * Author: Abdessamad EL FEDALI
 * Author URI: https://github.com/elfedali
 * Text Domain: optpress-wp-jwt
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Last Updated: March 19, 2026
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access not allowed.');
}

// Define plugin constants
define('OPTPRESS_JWT_VERSION', '1.2.0');
define('OPTPRESS_JWT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('OPTPRESS_JWT_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('OPTPRESS_JWT_PLUGIN_FILE', __FILE__);

// Check if JWT_AUTH_SECRET_KEY is defined
if (!defined('JWT_AUTH_SECRET_KEY')) {
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error is-dismissible">
            <p><strong>OptPress JWT:</strong> Please add JWT_AUTH_SECRET_KEY to your wp-config.php file.</p>
            <p><code>define(\'JWT_AUTH_SECRET_KEY\', \'' . wp_generate_password(64, false) . '\');</code></p>
            <p class="description">Copy the code above and add it to your wp-config.php file.</p>
        </div>';
    });
    return;
}

// Plugin activation hook
register_activation_hook(__FILE__, 'optpress_jwt_activate');
function optpress_jwt_activate() {
    optpress_jwt_create_tables();
    
    // Schedule cleanup event
    if (!wp_next_scheduled('optpress_jwt_cleanup_tokens')) {
        wp_schedule_event(time(), 'daily', 'optpress_jwt_cleanup_tokens');
    }
    
    flush_rewrite_rules();
}

// Plugin deactivation hook
register_deactivation_hook(__FILE__, 'optpress_jwt_deactivate');
function optpress_jwt_deactivate() {
    wp_clear_scheduled_hook('optpress_jwt_cleanup_tokens');
    flush_rewrite_rules();
}

// Create enhanced database tables
function optpress_jwt_create_tables() {
    global $wpdb;
    
    $charset_collate = $wpdb->get_charset_collate();
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    
    // Refresh tokens table
    $refresh_tokens_table = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
    
    $sql1 = "CREATE TABLE IF NOT EXISTS $refresh_tokens_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id bigint(20) UNSIGNED NOT NULL,
        token_hash varchar(255) NOT NULL,
        expires_at datetime NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        device_info varchar(255) DEFAULT '',
        ip_address varchar(45) DEFAULT '',
        user_agent text,
        is_revoked tinyint(1) DEFAULT 0,
        PRIMARY KEY (id),
        UNIQUE KEY token_hash (token_hash),
        KEY user_id (user_id),
        KEY expires_at (expires_at),
        KEY user_id_active (user_id, is_revoked, expires_at),
        KEY ip_address (ip_address)
    ) $charset_collate;";
    
    dbDelta($sql1);
    
    // User sessions table
    $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
    
    $sql2 = "CREATE TABLE IF NOT EXISTS $sessions_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id bigint(20) UNSIGNED NOT NULL,
        session_id varchar(255) NOT NULL,
        device_info varchar(255) DEFAULT '',
        ip_address varchar(45) DEFAULT '',
        last_activity datetime DEFAULT CURRENT_TIMESTAMP,
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY session_id (session_id),
        KEY last_activity (last_activity)
    ) $charset_collate;";
    
    dbDelta($sql2);
    
    // Login attempts table
    $login_attempts_table = $wpdb->prefix . 'optpress_jwt_login_attempts';
    
    $sql3 = "CREATE TABLE IF NOT EXISTS $login_attempts_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        username varchar(60) NOT NULL,
        ip_address varchar(45) NOT NULL,
        attempt_time datetime DEFAULT CURRENT_TIMESTAMP,
        user_agent text,
        PRIMARY KEY (id),
        KEY username (username),
        KEY ip_address (ip_address),
        KEY attempt_time (attempt_time)
    ) $charset_collate;";
    
    dbDelta($sql3);
    
    // Security logs table
    $security_logs_table = $wpdb->prefix . 'optpress_jwt_security_logs';
    
    $sql4 = "CREATE TABLE IF NOT EXISTS $security_logs_table (
        id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        event_type varchar(50) NOT NULL,
        username varchar(60) DEFAULT '',
        ip_address varchar(45) NOT NULL,
        user_agent text,
        details text,
        event_time datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY event_type (event_type),
        KEY username (username),
        KEY ip_address (ip_address),
        KEY event_time (event_time)
    ) $charset_collate;";
    
    dbDelta($sql4);
}

// Include JWT library
require_once OPTPRESS_JWT_PLUGIN_PATH . 'includes/class-jwt.php';

/**
 * Main JWT Authentication Class
 * 
 * Handles JWT token generation, validation, refresh, and user session management
 * with enhanced security features including rate limiting, comprehensive logging,
 * and configurable settings.
 * 
 * @since 1.0.0
 * @author Abdessamad
 */
class OptPress_WP_JWT_Auth {
    
    /**
     * JWT secret key for token signing
     * @var string
     */
    private $secret_key;
    
    /**
     * JWT algorithm for token signing
     * @var string
     */
    private $algorithm = 'HS256';
    
    /**
     * Plugin instance
     * @var OptPress_WP_JWT_Auth
     */
    private static $instance = null;
    
    // Security Configuration Constants
    const ACCESS_TOKEN_EXPIRY = 3600; // 1 hour
    const REFRESH_TOKEN_EXPIRY = 2592000; // 30 days
    const SESSION_CLEANUP_DAYS = 30;
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOGIN_ATTEMPT_WINDOW = 900; // 15 minutes
    const MAX_REFRESH_TOKENS_PER_USER = 10;
    
    /**
     * Get plugin instance (Singleton pattern)
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor - Initialize JWT authentication
     */
    private function __construct() {
        $this->secret_key = JWT_AUTH_SECRET_KEY;
        $this->validate_secret_key();
        $this->init_hooks();
    }
    
    /**
     * Validate the secret key strength
     */
    private function validate_secret_key() {
        if (strlen($this->secret_key) < 32) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-warning is-dismissible">
                    <p><strong>OptPress JWT:</strong> Your JWT secret key should be at least 32 characters long for better security.</p>
                    <p class="description">Current length: ' . strlen(JWT_AUTH_SECRET_KEY) . ' characters. Recommended: 64+ characters.</p>
                </div>';
            });
        }
    }
    
    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        add_action('rest_api_init', [$this, 'register_routes']);
        add_filter('determine_current_user', [$this, 'determine_current_user'], 10);
        add_filter('rest_authentication_errors', [$this, 'rest_authentication_errors']);
        add_action('wp_login', [$this, 'track_user_login'], 10, 2);
        add_action('wp_logout', [$this, 'track_user_logout']);
        
        // Admin settings
        if (is_admin()) {
            add_action('admin_menu', [$this, 'add_admin_menu']);
            add_action('admin_init', [$this, 'settings_init']);
            add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        }
        
        // Cleanup expired tokens daily
        add_action('wp', [$this, 'schedule_cleanup']);
        add_action('optpress_jwt_cleanup_tokens', [$this, 'cleanup_expired_tokens']);
    }
    
    /**
     * Register REST API routes
     */
    public function register_routes() {
        $namespace = 'auth-jwt/v1';
        
        // Authentication endpoints
        register_rest_route($namespace, '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'generate_token'],
            'permission_callback' => '__return_true',
            'args' => [
                'username' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                    'validate_callback' => function($value) {
                        return !empty($value);
                    }
                ],
                'password' => [
                    'required' => true,
                    'type' => 'string',
                ],
                'device_info' => [
                    'required' => false,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                    'default' => ''
                ],
            ]
        ]);
        
        register_rest_route($namespace, '/token/validate', [
            'methods' => 'POST',
            'callback' => [$this, 'validate_token'],
            'permission_callback' => '__return_true'
        ]);
        
        register_rest_route($namespace, '/token/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'refresh_token'],
            'permission_callback' => '__return_true',
            'args' => [
                'refresh_token' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
            ]
        ]);
        
        register_rest_route($namespace, '/logout', [
            'methods' => 'POST',
            'callback' => [$this, 'logout_user'],
            'permission_callback' => [$this, 'check_authentication']
        ]);
        
        register_rest_route($namespace, '/user/sessions', [
            'methods' => 'GET',
            'callback' => [$this, 'get_user_sessions'],
            'permission_callback' => [$this, 'check_authentication']
        ]);
        
        register_rest_route($namespace, '/user/sessions/revoke', [
            'methods' => 'POST',
            'callback' => [$this, 'revoke_all_sessions'],
            'permission_callback' => [$this, 'check_authentication']
        ]);
    }
    
    /**
     * Generate JWT token for authenticated user
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function generate_token($request) {
        // Enhanced input validation
        $username = sanitize_user($request->get_param('username'));
        $password = $request->get_param('password');
        $device_info = sanitize_text_field($request->get_param('device_info'));
        
        if (empty($username) || empty($password)) {
            return $this->error_response('missing_credentials', 'Username and password are required', 400);
        }
        
        // Check rate limiting
        if ($this->is_rate_limited($username)) {
            $this->log_security_event('rate_limit_exceeded', $username);
            return $this->error_response('rate_limited', 'Too many login attempts. Please try again later.', 429);
        }
        
        // Authenticate user
        $user = wp_authenticate($username, $password);
        
        if (is_wp_error($user)) {
            $this->log_failed_attempt($username);
            $this->log_security_event('authentication_failed', $username, $user->get_error_message());
            return $this->error_response('authentication_failed', $user->get_error_message(), 401);
        }
        
        // Check if user can access API
        if (!user_can($user, 'read')) {
            return $this->error_response('insufficient_permissions', 'User does not have sufficient permissions', 403);
        }
        
        // Check if user account is active
        if (!$this->is_user_active($user)) {
            return $this->error_response('account_inactive', 'User account is inactive', 403);
        }
        
        // Clear failed login attempts
        $this->clear_failed_attempts($username);
        
        // Generate tokens
        $access_token = $this->create_access_token($user);
        $refresh_token = $this->create_refresh_token($user, $device_info);
        
        // Track session
        $this->track_session($user, $device_info);
        
        // Log successful authentication
        $this->log_security_event('authentication_success', $username);
        
        $expiry = $this->get_config('access_token_expiry', self::ACCESS_TOKEN_EXPIRY);
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'token' => $access_token,
                'refresh_token' => $refresh_token,
                'user' => [
                    'id' => $user->ID,
                    'username' => $user->user_login,
                    'email' => $user->user_email,
                    'display_name' => $user->display_name,
                    'roles' => $user->roles,
                    'capabilities' => array_keys($user->get_role_caps()),
                ],
                'expires_in' => $expiry,
                'token_type' => 'Bearer'
            ]
        ]);
    }
    
    /**
     * Validate JWT token
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function validate_token($request) {
        $token = $this->get_token_from_request($request);
        
        if (!$token) {
            return $this->error_response('token_missing', 'Token not provided', 400);
        }
        
        try {
            $payload = JWT::decode($token, $this->secret_key, [$this->algorithm]);
            
            if (!isset($payload->data->user->id)) {
                return $this->error_response('invalid_token', 'Token does not contain valid user data', 401);
            }
            
            $user = get_user_by('id', $payload->data->user->id);
            
            if (!$user) {
                return $this->error_response('user_not_found', 'User not found', 404);
            }
            
            // Check if user is still active
            if (!$this->is_user_active($user)) {
                return $this->error_response('user_inactive', 'User account is no longer active', 403);
            }
            
            // Update last activity
            $this->update_user_activity($user->ID);
            
            return rest_ensure_response([
                'success' => true,
                'data' => [
                    'user_id' => $user->ID,
                    'username' => $user->user_login,
                    'email' => $user->user_email,
                    'display_name' => $user->display_name,
                    'roles' => $user->roles,
                    'expires' => $payload->exp,
                    'issued_at' => $payload->iat
                ]
            ]);
            
        } catch (Exception $e) {
            $error_message = $this->get_jwt_error_message($e->getMessage());
            $this->log_security_event('token_validation_failed', '', $error_message);
            return $this->error_response('invalid_token', $error_message, 401);
        }
    }
    
    /**
     * Refresh JWT token
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function refresh_token($request) {
        global $wpdb;
        
        $refresh_token = $request->get_param('refresh_token');
        
        if (empty($refresh_token)) {
            return $this->error_response('missing_refresh_token', 'Refresh token is required', 400);
        }
        
        $token_hash = hash('sha256', $refresh_token);
        
        // Find refresh token in database
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        $stored_token = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table_name WHERE token_hash = %s AND expires_at > NOW() AND is_revoked = 0",
            $token_hash
        ));
        
        if (!$stored_token) {
            $this->log_security_event('refresh_token_invalid', '', 'Invalid or expired refresh token');
            return $this->error_response('invalid_refresh_token', 'Invalid or expired refresh token', 401);
        }
        
        $user = get_user_by('id', $stored_token->user_id);
        
        if (!$user) {
            return $this->error_response('user_not_found', 'User not found', 404);
        }
        
        // Check if user is still active
        if (!$this->is_user_active($user)) {
            return $this->error_response('user_inactive', 'User account is no longer active', 403);
        }
        
        // Generate new tokens
        $new_access_token = $this->create_access_token($user);
        $new_refresh_token = $this->create_refresh_token($user, $stored_token->device_info);
        
        // Revoke old refresh token
        $wpdb->update(
            $table_name,
            ['is_revoked' => 1],
            ['id' => $stored_token->id],
            ['%d'],
            ['%d']
        );
        
        $expiry = $this->get_config('access_token_expiry', self::ACCESS_TOKEN_EXPIRY);
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'token' => $new_access_token,
                'refresh_token' => $new_refresh_token,
                'expires_in' => $expiry,
                'token_type' => 'Bearer'
            ]
        ]);
    }
    
    /**
     * Logout user and revoke all tokens
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function logout_user($request) {
        global $wpdb;
        
        $user_id = get_current_user_id();
        
        if (!$user_id) {
            return $this->error_response('not_authenticated', 'User not authenticated', 401);
        }
        
        // Revoke all refresh tokens for this user
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        $wpdb->update(
            $table_name,
            ['is_revoked' => 1],
            ['user_id' => $user_id],
            ['%d'],
            ['%d']
        );
        
        // Remove all sessions
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        $wpdb->delete($sessions_table, ['user_id' => $user_id], ['%d']);
        
        $user = get_userdata($user_id);
        if ($user) {
            $this->log_security_event('user_logout', $user->user_login);
        }
        
        return rest_ensure_response([
            'success' => true,
            'message' => 'Successfully logged out from all devices'
        ]);
    }
    
    /**
     * Get user's active sessions
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function get_user_sessions($request) {
        global $wpdb;
        
        $user_id = get_current_user_id();
        
        if (!$user_id) {
            return $this->error_response('not_authenticated', 'User not authenticated', 401);
        }
        
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        
        $sessions = $wpdb->get_results($wpdb->prepare(
            "SELECT device_info, ip_address, last_activity, created_at 
             FROM $sessions_table 
             WHERE user_id = %d 
             ORDER BY last_activity DESC",
            $user_id
        ));
        
        return rest_ensure_response([
            'success' => true,
            'data' => $sessions
        ]);
    }
    
    /**
     * Revoke all user sessions except current
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function revoke_all_sessions($request) {
        global $wpdb;
        
        $user_id = get_current_user_id();
        
        if (!$user_id) {
            return $this->error_response('not_authenticated', 'User not authenticated', 401);
        }
        
        // Revoke all refresh tokens
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        $wpdb->update(
            $table_name,
            ['is_revoked' => 1],
            ['user_id' => $user_id],
            ['%d'],
            ['%d']
        );
        
        // Remove all sessions
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        $wpdb->delete($sessions_table, ['user_id' => $user_id], ['%d']);
        
        return rest_ensure_response([
            'success' => true,
            'message' => 'All sessions revoked successfully'
        ]);
    }
    
    /**
     * Create access token with enhanced security
     *
     * @param WP_User $user
     * @return string
     */
    private function create_access_token($user) {
        $issued_at = time();
        $expiry = $this->get_config('access_token_expiry', self::ACCESS_TOKEN_EXPIRY);
        $expiration = $issued_at + $expiry;
        $jti = wp_generate_uuid4(); // Unique token ID
        
        $payload = [
            'iss' => get_bloginfo('url'),
            'aud' => get_bloginfo('url'),
            'iat' => $issued_at,
            'exp' => $expiration,
            'nbf' => $issued_at, // Not before
            'jti' => $jti, // JWT ID for token tracking
            'data' => [
                'user' => [
                    'id' => $user->ID,
                    'username' => $user->user_login,
                    'email' => $user->user_email,
                    'roles' => $user->roles,
                ]
            ]
        ];
        
        return JWT::encode($payload, $this->secret_key, $this->algorithm);
    }
    
    /**
     * Create secure refresh token
     *
     * @param WP_User $user
     * @param string $device_info
     * @return string
     */
    private function create_refresh_token($user, $device_info = '') {
        global $wpdb;
        
        // Generate cryptographically secure token
        $refresh_token = bin2hex(random_bytes(32));
        $token_hash = hash('sha256', $refresh_token);
        $expiry = $this->get_config('refresh_token_expiry', self::REFRESH_TOKEN_EXPIRY);
        $expires_at = date('Y-m-d H:i:s', time() + $expiry);
        
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        
        // Limit refresh tokens per user
        $this->cleanup_user_refresh_tokens($user->ID, self::MAX_REFRESH_TOKENS_PER_USER - 1);
        
        $wpdb->insert(
            $table_name,
            [
                'user_id' => $user->ID,
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'device_info' => sanitize_text_field($device_info),
                'ip_address' => $this->get_client_ip(),
                'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? ''),
                'created_at' => current_time('mysql')
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s', '%s']
        );
        
        return $refresh_token;
    }
    
    /**
     * Cleanup old refresh tokens for user
     *
     * @param int $user_id
     * @param int $keep_count
     */
    private function cleanup_user_refresh_tokens($user_id, $keep_count = 9) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        
        // Get IDs of tokens to keep
        $tokens_to_keep = $wpdb->get_col($wpdb->prepare(
            "SELECT id FROM $table_name 
             WHERE user_id = %d AND is_revoked = 0 AND expires_at > NOW()
             ORDER BY created_at DESC 
             LIMIT %d",
            $user_id, $keep_count
        ));
        
        if (empty($tokens_to_keep)) {
            return;
        }
        
        $placeholders = implode(',', array_fill(0, count($tokens_to_keep), '%d'));
        
        // Delete old tokens
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table_name 
             WHERE user_id = %d 
             AND id NOT IN ($placeholders)",
            array_merge([$user_id], $tokens_to_keep)
        ));
    }
    
    /**
     * Track user session
     *
     * @param WP_User $user
     * @param string $device_info
     */
    private function track_session($user, $device_info = '') {
        global $wpdb;
        
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        $session_id = wp_generate_password(32, false);
        
        $wpdb->insert(
            $sessions_table,
            [
                'user_id' => $user->ID,
                'session_id' => $session_id,
                'device_info' => sanitize_text_field($device_info),
                'ip_address' => $this->get_client_ip(),
                'last_activity' => current_time('mysql'),
                'created_at' => current_time('mysql')
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s']
        );
    }
    
    /**
     * Determine current user from JWT token
     *
     * @param int|false $user_id
     * @return int|false
     */
    public function determine_current_user($user_id) {
        // If already determined, return it
        if ($user_id) {
            return $user_id;
        }
        
        // Don't authenticate for admin requests
        if (is_admin()) {
            return $user_id;
        }
        
        $token = $this->get_token_from_headers();
        
        if (!$token) {
            return $user_id;
        }
        
        try {
            $payload = JWT::decode($token, $this->secret_key, [$this->algorithm]);
            
            if (!isset($payload->data->user->id)) {
                return $user_id;
            }
            
            return $payload->data->user->id;
            
        } catch (Exception $e) {
            return $user_id;
        }
    }
    
    /**
     * Handle REST authentication errors
     *
     * @param WP_Error|null|true $result
     * @return WP_Error|null|true
     */
    public function rest_authentication_errors($result) {
        // If already an error, pass it through
        if (!empty($result)) {
            return $result;
        }
        
        global $wp;
        
        $route = $wp->query_vars['rest_route'] ?? '';
        
        // Skip authentication for public endpoints
        $public_routes = [
            '/auth-jwt/v1/token',
            '/auth-jwt/v1/token/refresh',
        ];
        
        foreach ($public_routes as $public_route) {
            if (strpos($route, $public_route) === 0) {
                return $result;
            }
        }
        
        $token = $this->get_token_from_headers();
        
        if (!$token) {
            return $result;
        }
        
        try {
            $payload = JWT::decode($token, $this->secret_key, [$this->algorithm]);
            return $result;
        } catch (Exception $e) {
            return new WP_Error('jwt_auth_invalid_token', $e->getMessage(), ['status' => 401]);
        }
    }
    
    /**
     * Check if user is authenticated
     *
     * @return bool
     */
    public function check_authentication() {
        return is_user_logged_in();
    }
    
    /**
     * Get token from request headers
     *
     * @return string|false
     */
    private function get_token_from_headers() {
        $auth_header = null;
        
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['Authorization'])) {
                $auth_header = $headers['Authorization'];
            }
        }
        
        if (!$auth_header) {
            return false;
        }
        
        $auth_parts = explode(' ', $auth_header, 2);
        
        if (count($auth_parts) !== 2) {
            return false;
        }
        
        list($type, $token) = $auth_parts;
        
        if (strtolower($type) !== 'bearer') {
            return false;
        }
        
        return $token;
    }
    
    /**
     * Get token from REST request
     *
     * @param WP_REST_Request $request
     * @return string|false
     */
    private function get_token_from_request($request) {
        $auth_header = $request->get_header('authorization');
        
        if (!$auth_header) {
            return false;
        }
        
        $auth_parts = explode(' ', $auth_header, 2);
        
        if (count($auth_parts) !== 2) {
            return false;
        }
        
        list($type, $token) = $auth_parts;
        
        if (strtolower($type) !== 'bearer') {
            return false;
        }
        
        return $token;
    }
    
    /**
     * Standardized error response
     *
     * @param string $code
     * @param string $message
     * @param int $status
     * @return WP_Error
     */
    private function error_response($code, $message, $status = 400) {
        return new WP_Error($code, $message, [
            'status' => $status,
            'timestamp' => current_time('mysql'),
            'ip' => $this->get_client_ip()
        ]);
    }
    
    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $ip_keys = [
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Get first IP if multiple are present
                if (strpos($ip, ',') !== false) {
                    $ip = explode(',', $ip)[0];
                }
                $ip = trim($ip);
                // Validate IP address
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    /**
     * Check if user is rate limited
     *
     * @param string $username
     * @return bool
     */
    private function is_rate_limited($username) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_login_attempts';
        $ip_address = $this->get_client_ip();
        $max_attempts = $this->get_config('max_login_attempts', self::MAX_LOGIN_ATTEMPTS);
        
        $attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name 
             WHERE (username = %s OR ip_address = %s) 
             AND attempt_time > DATE_SUB(NOW(), INTERVAL %d SECOND)",
            $username, $ip_address, self::LOGIN_ATTEMPT_WINDOW
        ));
        
        return $attempts >= $max_attempts;
    }
    
    /**
     * Log failed login attempt
     *
     * @param string $username
     */
    private function log_failed_attempt($username) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_login_attempts';
        
        $wpdb->insert(
            $table_name,
            [
                'username' => $username,
                'ip_address' => $this->get_client_ip(),
                'attempt_time' => current_time('mysql'),
                'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? '')
            ],
            ['%s', '%s', '%s', '%s']
        );
    }
    
    /**
     * Clear failed login attempts for user
     *
     * @param string $username
     */
    private function clear_failed_attempts($username) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_login_attempts';
        $ip_address = $this->get_client_ip();
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table_name WHERE username = %s OR ip_address = %s",
            $username, $ip_address
        ));
    }
    
    /**
     * Check if user account is active
     *
     * @param WP_User $user
     * @return bool
     */
    private function is_user_active($user) {
        // Check if user is not spammed or deleted
        $user_status = get_user_meta($user->ID, 'user_status', true);
        
        if (!empty($user_status) && $user_status !== '0') {
            return false;
        }
        
        // Check if user has spam flag (multisite)
        if (is_multisite() && get_user_meta($user->ID, 'spam', true)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Update user's last activity
     *
     * @param int $user_id
     */
    private function update_user_activity($user_id) {
        global $wpdb;
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        
        $wpdb->update(
            $sessions_table,
            ['last_activity' => current_time('mysql')],
            ['user_id' => $user_id],
            ['%s'],
            ['%d']
        );
    }
    
    /**
     * Get user-friendly JWT error message
     *
     * @param string $technical_message
     * @return string
     */
    private function get_jwt_error_message($technical_message) {
        if (strpos($technical_message, 'Expired token') !== false) {
            return 'Token has expired';
        }
        if (strpos($technical_message, 'Wrong number of segments') !== false) {
            return 'Invalid token format';
        }
        if (strpos($technical_message, 'Invalid signature') !== false) {
            return 'Invalid token signature';
        }
        if (strpos($technical_message, 'Before') !== false) {
            return 'Token not yet valid';
        }
        return 'Invalid token';
    }
    
    /**
     * Track user login
     *
     * @param string $user_login
     * @param WP_User $user
     */
    public function track_user_login($user_login, $user) {
        // Update last activity for this user's sessions
        $this->update_user_activity($user->ID);
    }
    
    /**
     * Track user logout
     */
    public function track_user_logout() {
        // Could add logout tracking here if needed
    }
    
    /**
     * Schedule cleanup task
     */
    public function schedule_cleanup() {
        if (!wp_next_scheduled('optpress_jwt_cleanup_tokens')) {
            wp_schedule_event(time(), 'daily', 'optpress_jwt_cleanup_tokens');
        }
    }
    
    /**
     * Cleanup expired tokens and old data with batch processing
     */
    public function cleanup_expired_tokens() {
        global $wpdb;
        
        // Clean up in batches to avoid memory issues
        $batch_size = 1000;
        
        // Delete expired refresh tokens
        $table_name = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        do {
            $deleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM $table_name 
                 WHERE (expires_at < NOW() OR is_revoked = 1) 
                 LIMIT %d",
                $batch_size
            ));
        } while ($deleted > 0);
        
        // Delete old sessions
        $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
        do {
            $deleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM $sessions_table 
                 WHERE last_activity < DATE_SUB(NOW(), INTERVAL %d DAY) 
                 LIMIT %d",
                self::SESSION_CLEANUP_DAYS,
                $batch_size
            ));
        } while ($deleted > 0);
        
        // Clean up old login attempts
        $attempts_table = $wpdb->prefix . 'optpress_jwt_login_attempts';
        do {
            $deleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM $attempts_table 
                 WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 7 DAY) 
                 LIMIT %d",
                $batch_size
            ));
        } while ($deleted > 0);
        
        // Clean up old security logs (keep 90 days)
        $security_logs_table = $wpdb->prefix . 'optpress_jwt_security_logs';
        do {
            $deleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM $security_logs_table 
                 WHERE event_time < DATE_SUB(NOW(), INTERVAL 90 DAY) 
                 LIMIT %d",
                $batch_size
            ));
        } while ($deleted > 0);
        
        // Log cleanup activity
        error_log('OptPress JWT: Cleanup completed successfully at ' . current_time('mysql'));
    }
    
    /**
     * Add admin menu for JWT settings
     */
    public function add_admin_menu() {
        add_options_page(
            'OptPress JWT',
            'OptPress JWT',
            'manage_options',
            'optpress-jwt-settings',
            [$this, 'settings_page']
        );
    }
    
    /**
     * Initialize settings
     */
    public function settings_init() {
        register_setting('optpress_jwt_settings', 'optpress_jwt_options', [
            'sanitize_callback' => [$this, 'sanitize_settings']
        ]);
        
        add_settings_section(
            'optpress_jwt_security_section',
            'Security Settings',
            function() {
                echo '<p>Configure JWT authentication security settings.</p>';
            },
            'optpress_jwt_settings'
        );
        
        add_settings_field(
            'access_token_expiry',
            'Access Token Expiry (seconds)',
            [$this, 'access_token_expiry_field'],
            'optpress_jwt_settings',
            'optpress_jwt_security_section'
        );
        
        add_settings_field(
            'refresh_token_expiry',
            'Refresh Token Expiry (seconds)',
            [$this, 'refresh_token_expiry_field'],
            'optpress_jwt_settings',
            'optpress_jwt_security_section'
        );
        
        add_settings_field(
            'max_login_attempts',
            'Max Login Attempts',
            [$this, 'max_login_attempts_field'],
            'optpress_jwt_settings',
            'optpress_jwt_security_section'
        );
    }

    /**
     * Enqueue admin assets for plugin settings page
     *
     * @param string $hook_suffix
     */
    public function enqueue_admin_assets($hook_suffix) {
        // Only load assets on our settings page
        if (!isset($_GET['page']) || $_GET['page'] !== 'optpress-jwt-settings') {
            return;
        }

        wp_enqueue_style('optpress-jwt-admin', OPTPRESS_JWT_PLUGIN_URL . 'assets/admin.css', [], OPTPRESS_JWT_VERSION);
        wp_enqueue_script('optpress-jwt-admin', OPTPRESS_JWT_PLUGIN_URL . 'assets/admin.js', ['jquery'], OPTPRESS_JWT_VERSION, true);
    }
    
    /**
     * Settings page HTML
     */
    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Settings saved handled by WP; display any settings errors if present
        settings_errors('optpress_jwt_messages');
        ?>
        <?php
        // Real data
        $key_len      = strlen(JWT_AUTH_SECRET_KEY);
        $sessions_24h = $this->get_active_sessions_count();
        $active_rt    = $this->get_active_refresh_tokens_count();
        $access_expiry  = $this->get_config('access_token_expiry',  self::ACCESS_TOKEN_EXPIRY);
        $refresh_expiry = $this->get_config('refresh_token_expiry', self::REFRESH_TOKEN_EXPIRY);
        $curl_example   = 'curl -s -X POST "' . rest_url('auth-jwt/v1/token') . '" \\' . "\n" .
                          '  -H "Content-Type: application/json" \\' . "\n" .
                          '  -d \'{"username":"your_username","password":"your_password","device_info":"iPhone 15"}\'';
        if ($key_len >= 64)      { $key_badge = 'opjwt-badge-ok';     $key_label = 'Excellent'; }
        elseif ($key_len >= 32)  { $key_badge = 'opjwt-badge-warn';   $key_label = 'Good'; }
        else                     { $key_badge = 'opjwt-badge-danger';  $key_label = 'Weak'; }
        ?>
        <div class="wrap opjwt-wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?> <span class="opjwt-badge">v<?php echo esc_html(OPTPRESS_JWT_VERSION); ?></span></h1>

            <div class="opjwt-tabs">
                <button type="button" class="opjwt-tab-btn" data-tab="dashboard"><?php _e('Dashboard', 'optpress-wp-jwt'); ?></button>
                <button type="button" class="opjwt-tab-btn" data-tab="settings"><?php _e('OptPress JWT', 'optpress-wp-jwt'); ?></button>
                <button type="button" class="opjwt-tab-btn" data-tab="docs"><?php _e('API Docs', 'optpress-wp-jwt'); ?></button>
                <button type="button" class="opjwt-tab-btn" data-tab="logs"><?php _e('Security Logs', 'optpress-wp-jwt'); ?></button>
                <button type="button" class="opjwt-tab-btn" data-tab="sessions"><?php _e('Sessions', 'optpress-wp-jwt'); ?></button>
            </div>

            <!-- ── DASHBOARD ───────────────────────────── -->
            <div id="opjwt-tab-dashboard" class="opjwt-tab-panel">
                <div class="opjwt-stats-grid">
                    <div class="opjwt-stat-card opjwt-stat-blue">
                        <div class="opjwt-stat-label"><?php _e('Plugin Version', 'optpress-wp-jwt'); ?></div>
                        <div class="opjwt-stat-value"><?php echo esc_html(OPTPRESS_JWT_VERSION); ?></div>
                        <div class="opjwt-stat-sub">PHP <?php echo esc_html(PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION); ?> &bull; WP <?php echo esc_html(get_bloginfo('version')); ?></div>
                    </div>
                    <div class="opjwt-stat-card opjwt-stat-<?php echo $key_len >= 64 ? 'green' : ($key_len >= 32 ? 'orange' : 'red'); ?>">
                        <div class="opjwt-stat-label"><?php _e('Secret Key', 'optpress-wp-jwt'); ?></div>
                        <div class="opjwt-stat-value"><?php echo $key_len; ?> <span style="font-size:14px;font-weight:500;">chars</span></div>
                        <div class="opjwt-stat-sub"><span class="<?php echo $key_badge; ?>"><?php echo $key_label; ?></span></div>
                    </div>
                    <div class="opjwt-stat-card opjwt-stat-blue">
                        <div class="opjwt-stat-label"><?php _e('Active Sessions (24h)', 'optpress-wp-jwt'); ?></div>
                        <div class="opjwt-stat-value"><?php echo $sessions_24h; ?></div>
                        <div class="opjwt-stat-sub"><?php _e('Unique devices logged in', 'optpress-wp-jwt'); ?></div>
                    </div>
                    <div class="opjwt-stat-card opjwt-stat-blue">
                        <div class="opjwt-stat-label"><?php _e('Active Refresh Tokens', 'optpress-wp-jwt'); ?></div>
                        <div class="opjwt-stat-value"><?php echo $active_rt; ?></div>
                        <div class="opjwt-stat-sub"><?php _e('Valid & non-revoked', 'optpress-wp-jwt'); ?></div>
                    </div>
                </div>

                <div class="opjwt-status-grid">
                    <table class="opjwt-info-table">
                        <tr><th colspan="2"><?php _e('System Info', 'optpress-wp-jwt'); ?></th></tr>
                        <tr><td><?php _e('API Base URL', 'optpress-wp-jwt'); ?></td><td><code><?php echo esc_url(rest_url('auth-jwt/v1')); ?></code></td></tr>
                        <tr><td><?php _e('Algorithm', 'optpress-wp-jwt'); ?></td><td><span class="opjwt-badge-info">HS256</span></td></tr>
                        <tr><td><?php _e('Access Token Expiry', 'optpress-wp-jwt'); ?></td><td><?php echo esc_html(human_time_diff(0, $access_expiry)); ?> <span style="color:#787c82">(<?php echo $access_expiry; ?>s)</span></td></tr>
                        <tr><td><?php _e('Refresh Token Expiry', 'optpress-wp-jwt'); ?></td><td><?php echo esc_html(human_time_diff(0, $refresh_expiry)); ?> <span style="color:#787c82">(<?php echo $refresh_expiry; ?>s)</span></td></tr>
                        <tr><td><?php _e('Max Login Attempts', 'optpress-wp-jwt'); ?></td><td><?php echo esc_html($this->get_config('max_login_attempts', self::MAX_LOGIN_ATTEMPTS)); ?> <?php _e('per 15 min', 'optpress-wp-jwt'); ?></td></tr>
                        <tr><td><?php _e('Secret Strength', 'optpress-wp-jwt'); ?></td><td><span class="<?php echo $key_badge; ?>"><?php echo $key_label; ?></span> &mdash; <?php echo $key_len; ?> chars</td></tr>
                        <tr><td><?php _e('PHP Version', 'optpress-wp-jwt'); ?></td><td><?php echo esc_html(PHP_VERSION); ?></td></tr>
                        <tr><td><?php _e('WordPress Version', 'optpress-wp-jwt'); ?></td><td><?php echo esc_html(get_bloginfo('version')); ?></td></tr>
                    </table>

                    <div>
                        <div class="opjwt-settings-card">
                            <h3><?php _e('Example cURL — Get Token', 'optpress-wp-jwt'); ?></h3>
                            <div class="opjwt-endpoint-block" id="opjwt-endpoint-curl"><?php echo esc_html($curl_example); ?></div>
                            <button class="button opjwt-copy-btn" data-target="opjwt-endpoint-curl"><?php _e('Copy', 'optpress-wp-jwt'); ?></button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ── SETTINGS ────────────────────────────── -->
            <div id="opjwt-tab-settings" class="opjwt-tab-panel">
                <div class="opjwt-settings-card">
                    <form method="post" action="options.php">
                        <?php
                        settings_fields('optpress_jwt_settings');
                        do_settings_sections('optpress_jwt_settings');
                        submit_button(__('Save Settings', 'optpress-wp-jwt'));
                        ?>
                    </form>
                </div>
            </div>

            <!-- ── API DOCS ─────────────────────────────── -->
            <div id="opjwt-tab-docs" class="opjwt-tab-panel">
                <div class="opjwt-settings-card">
                    <h3><?php _e('REST API Endpoints', 'optpress-wp-jwt'); ?></h3>
                    <p><?php _e('Send all requests with <code>Content-Type: application/json</code>. Protected endpoints require an <code>Authorization: Bearer &lt;token&gt;</code> header.', 'optpress-wp-jwt'); ?></p>
                    <table class="opjwt-info-table opjwt-endpoint-table">
                        <tr><th><?php _e('Method', 'optpress-wp-jwt'); ?></th><th><?php _e('Endpoint', 'optpress-wp-jwt'); ?></th><th><?php _e('Auth?', 'optpress-wp-jwt'); ?></th><th><?php _e('Description', 'optpress-wp-jwt'); ?></th></tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-post">POST</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/token')); ?></code></td>
                            <td><span class="opjwt-badge-ok">Public</span></td>
                            <td><?php _e('Login — returns <code>token</code> + <code>refresh_token</code>.', 'optpress-wp-jwt'); ?></td>
                        </tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-post">POST</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/token/validate')); ?></code></td>
                            <td><span class="opjwt-badge-ok">Public</span></td>
                            <td><?php _e('Validate an access token and return the user info.', 'optpress-wp-jwt'); ?></td>
                        </tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-post">POST</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/token/refresh')); ?></code></td>
                            <td><span class="opjwt-badge-ok">Public</span></td>
                            <td><?php _e('Exchange a refresh token for a new access token (rotates token).', 'optpress-wp-jwt'); ?></td>
                        </tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-post">POST</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/logout')); ?></code></td>
                            <td><span class="opjwt-badge-warn">Bearer</span></td>
                            <td><?php _e('Revoke all tokens and sessions for the current user.', 'optpress-wp-jwt'); ?></td>
                        </tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-get">GET</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/user/sessions')); ?></code></td>
                            <td><span class="opjwt-badge-warn">Bearer</span></td>
                            <td><?php _e('List active sessions for the authenticated user.', 'optpress-wp-jwt'); ?></td>
                        </tr>
                        <tr>
                            <td><span class="opjwt-method opjwt-method-post">POST</span></td>
                            <td><code><?php echo esc_url(rest_url('auth-jwt/v1/user/sessions/revoke')); ?></code></td>
                            <td><span class="opjwt-badge-warn">Bearer</span></td>
                            <td><?php _e('Revoke all sessions for the authenticated user.', 'optpress-wp-jwt'); ?></td>
                        </tr>
                    </table>

                    <h3 style="margin-top:24px;"><?php _e('Request Body — Login', 'optpress-wp-jwt'); ?></h3>
                    <div class="opjwt-endpoint-block"><?php echo esc_html("POST " . rest_url('auth-jwt/v1/token') . "\n\n{\n  \"username\": \"john\",\n  \"password\": \"secret\",\n  \"device_info\": \"iPhone 15\"  // optional\n}"); ?></div>

                    <h3 style="margin-top:24px;"><?php _e('Using the Token', 'optpress-wp-jwt'); ?></h3>
                    <div class="opjwt-endpoint-block"><?php echo esc_html("GET " . rest_url('wp/v2/posts') . "\nAuthorization: Bearer <your_access_token>"); ?></div>
                </div>
            </div>

            <!-- ── SECURITY LOGS ────────────────────────── -->
            <div id="opjwt-tab-logs" class="opjwt-tab-panel">
                <div class="opjwt-logs-wrap">
                    <div class="opjwt-logs-toolbar">
                        <h3><?php _e('Recent Security Events', 'optpress-wp-jwt'); ?></h3>
                        <div><?php printf(__('Last %d events &bull; Kept for 90 days', 'optpress-wp-jwt'), 50); ?></div>
                    </div>
                    <?php $logs = $this->get_security_logs(50); ?>
                    <?php if (empty($logs)) : ?>
                        <table class="opjwt-data-table"><tbody><tr class="opjwt-empty-row"><td colspan="5"><?php _e('No security events recorded yet.', 'optpress-wp-jwt'); ?></td></tr></tbody></table>
                    <?php else: ?>
                        <table class="opjwt-data-table">
                            <thead><tr>
                                <th><?php _e('Time', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('Event', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('User', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('IP Address', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('Details', 'optpress-wp-jwt'); ?></th>
                            </tr></thead>
                            <tbody>
                            <?php foreach ($logs as $row): ?>
                                <tr>
                                    <td style="white-space:nowrap;"><?php echo esc_html($row->event_time); ?></td>
                                    <td><span class="opjwt-event-<?php echo esc_attr($row->event_type); ?>"><?php echo esc_html(str_replace('_', ' ', $row->event_type)); ?></span></td>
                                    <td><?php echo $row->username ? esc_html($row->username) : '<em style="color:#787c82">—</em>'; ?></td>
                                    <td><code><?php echo esc_html($row->ip_address); ?></code></td>
                                    <td style="color:#50575e;"><?php echo esc_html($row->details); ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>

            <!-- ── SESSIONS ─────────────────────────────── -->
            <div id="opjwt-tab-sessions" class="opjwt-tab-panel">
                <?php
                global $wpdb;
                $sessions_table = $wpdb->prefix . 'optpress_jwt_sessions';
                $recent_sessions = $wpdb->get_results(
                    "SELECT s.*, u.user_login FROM {$sessions_table} s
                     LEFT JOIN {$wpdb->users} u ON u.ID = s.user_id
                     ORDER BY s.last_activity DESC LIMIT 50"
                );
                ?>
                <div class="opjwt-logs-wrap">
                    <div class="opjwt-logs-toolbar">
                        <h3><?php printf(__('Recent Sessions &mdash; %d total (24h)', 'optpress-wp-jwt'), $sessions_24h); ?></h3>
                        <div><?php _e('Showing last 50 sessions', 'optpress-wp-jwt'); ?></div>
                    </div>
                    <?php if (empty($recent_sessions)) : ?>
                        <table class="opjwt-data-table"><tbody><tr class="opjwt-empty-row"><td colspan="5"><?php _e('No sessions found.', 'optpress-wp-jwt'); ?></td></tr></tbody></table>
                    <?php else: ?>
                        <table class="opjwt-data-table">
                            <thead><tr>
                                <th><?php _e('User', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('Device', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('IP Address', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('Last Activity', 'optpress-wp-jwt'); ?></th>
                                <th><?php _e('Created', 'optpress-wp-jwt'); ?></th>
                            </tr></thead>
                            <tbody>
                            <?php foreach ($recent_sessions as $s): ?>
                                <tr>
                                    <td><strong><?php echo esc_html($s->user_login ?: 'User #' . $s->user_id); ?></strong></td>
                                    <td><?php echo $s->device_info ? esc_html($s->device_info) : '<em style="color:#787c82">' . __('Unknown', 'optpress-wp-jwt') . '</em>'; ?></td>
                                    <td><code><?php echo esc_html($s->ip_address); ?></code></td>
                                    <td style="white-space:nowrap;"><?php echo esc_html($s->last_activity); ?></td>
                                    <td style="white-space:nowrap;color:#787c82;"><?php echo esc_html($s->created_at); ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>

        </div>
        <?php
    }
    
    /**
     * Get configuration value with fallback
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    private function get_config($key, $default = null) {
        $options = get_option('optpress_jwt_options', []);
        return $options[$key] ?? $default;
    }
    
    /**
     * Form field callbacks
     */
    public function access_token_expiry_field() {
        $value = $this->get_config('access_token_expiry', self::ACCESS_TOKEN_EXPIRY);
        echo "<input type='number' name='optpress_jwt_options[access_token_expiry]' value='" . esc_attr($value) . "' min='300' max='86400' class='regular-text' />";
        echo "<p class='description'>Token validity in seconds (5 minutes to 24 hours). Default: 3600 (1 hour)</p>";
    }
    
    public function refresh_token_expiry_field() {
        $value = $this->get_config('refresh_token_expiry', self::REFRESH_TOKEN_EXPIRY);
        echo "<input type='number' name='optpress_jwt_options[refresh_token_expiry]' value='" . esc_attr($value) . "' min='86400' max='7776000' class='regular-text' />";
        echo "<p class='description'>Refresh token validity in seconds (1 day to 90 days). Default: 2592000 (30 days)</p>";
    }
    
    public function max_login_attempts_field() {
        $value = $this->get_config('max_login_attempts', self::MAX_LOGIN_ATTEMPTS);
        echo "<input type='number' name='optpress_jwt_options[max_login_attempts]' value='" . esc_attr($value) . "' min='3' max='20' class='regular-text' />";
        echo "<p class='description'>Maximum failed login attempts before rate limiting. Default: 5</p>";
    }
    
    /**
     * Sanitize settings
     *
     * @param array $input
     * @return array
     */
    public function sanitize_settings($input) {
        $sanitized = [];
        
        $sanitized['access_token_expiry'] = max(300, min(86400, absint($input['access_token_expiry'] ?? self::ACCESS_TOKEN_EXPIRY)));
        $sanitized['refresh_token_expiry'] = max(86400, min(7776000, absint($input['refresh_token_expiry'] ?? self::REFRESH_TOKEN_EXPIRY)));
        $sanitized['max_login_attempts'] = max(3, min(20, absint($input['max_login_attempts'] ?? self::MAX_LOGIN_ATTEMPTS)));
        
        return $sanitized;
    }
    
    /**
     * Get system statistics
     */
    private function get_active_sessions_count() {
        global $wpdb;
        $table = $wpdb->prefix . 'optpress_jwt_sessions';
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE last_activity > DATE_SUB(NOW(), INTERVAL 1 DAY)");
    }
    
    private function get_active_refresh_tokens_count() {
        global $wpdb;
        $table = $wpdb->prefix . 'optpress_jwt_refresh_tokens';
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE expires_at > NOW() AND is_revoked = 0");
    }
    
    /**
     * Log security events
     * 
     * @param string $event_type Type of security event
     * @param string $username Username involved
     * @param string $details Additional event details
     */
    private function log_security_event($event_type, $username = '', $details = '') {
        $log_entry = sprintf(
            '[%s] JWT Security Event: %s | User: %s | IP: %s | User-Agent: %s | Details: %s',
            current_time('mysql'),
            $event_type,
            $username,
            $this->get_client_ip(),
            sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'),
            $details
        );
        
        // Log to WordPress error log
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log($log_entry);
        }
        
        // Store critical events in database for monitoring
        if (in_array($event_type, ['authentication_failed', 'rate_limit_exceeded', 'token_validation_failed', 'refresh_token_invalid'])) {
            $this->store_security_log($event_type, $username, $details);
        }
        
        // Hook for external monitoring systems
        do_action('optpress_jwt_security_event', $event_type, $username, $details, $this->get_client_ip());
    }
    
    /**
     * Store security log in database
     *
     * @param string $event_type
     * @param string $username
     * @param string $details
     */
    private function store_security_log($event_type, $username, $details) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_security_logs';
        
        $wpdb->insert(
            $table_name,
            [
                'event_type' => $event_type,
                'username' => $username,
                'ip_address' => $this->get_client_ip(),
                'user_agent' => sanitize_text_field($_SERVER['HTTP_USER_AGENT'] ?? ''),
                'details' => $details,
                'event_time' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );
    }
    
    /**
     * Get security logs for admin review
     *
     * @param int $limit
     * @return array
     */
    public function get_security_logs($limit = 100) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'optpress_jwt_security_logs';
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table_name ORDER BY event_time DESC LIMIT %d",
            $limit
        ), ARRAY_A);
    }
}

// Initialize the plugin
OptPress_WP_JWT_Auth::get_instance();

/**
 * Enhanced CORS support with security headers
 */
function optpress_jwt_cors_headers() {
    // Get allowed origins from settings or default
    $allowed_origins = apply_filters('optpress_jwt_allowed_origins', ['*']);
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    
    if (in_array('*', $allowed_origins) || in_array($origin, $allowed_origins)) {
        header('Access-Control-Allow-Origin: ' . ($origin ?: '*'));
    }
    
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-WP-Nonce');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 3600');
    
    // Security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit(0);
    }
}

add_action('rest_api_init', function() {
    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
    add_filter('rest_pre_serve_request', function($value) {
        optpress_jwt_cors_headers();
        return $value;
    });
}, 15);

// Load text domain for translations
function optpress_jwt_load_textdomain() {
    load_plugin_textdomain('optpress-wp-jwt', false, dirname(plugin_basename(__FILE__)) . '/languages');
}
add_action('plugins_loaded', 'optpress_jwt_load_textdomain');

// Add Settings link to the plugin action links in the plugins list
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'optpress_jwt_action_links');
function optpress_jwt_action_links($links) {
    $settings_link = '<a href="' . esc_url(admin_url('options-general.php?page=optpress-jwt-settings')) . '">' . __('Settings', 'optpress-wp-jwt') . '</a>';
    $links[] = $settings_link;
    return $links;
}
