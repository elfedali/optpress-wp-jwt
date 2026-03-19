 # OptPress JWT

 A lightweight, secure JWT authentication plugin for WordPress with first-class mobile app support: short-lived access tokens, refresh tokens, session management, rate limiting, and admin configuration.

 Quick reference: Base REST API prefix: `/wp-json/auth-jwt/v1`

 Contents
 - Features
 - Requirements
 - Install & configure
 - API endpoints (examples)
 - Mobile integration snippets
 - Troubleshooting & support

 Features
 - Short-lived access tokens (configurable)
 - Refresh tokens with token rotation and DB storage (hashed)
 - Session management (device tracking, revoke sessions)
 - Rate limiting and failed-login protection
 - Security logging / audit trail
 - Admin settings page and system status
 - CORS support for mobile apps

 Requirements
 - WordPress 5.0+
 - PHP 7.4+
 - PHP extensions: json, openssl

 Install & configure
 1) Copy plugin folder to `wp-content/plugins/optpress-jwt` and activate the plugin in WP admin.
 2) Add a strong secret to `wp-config.php` (required):

 ```php
 // JWT secret (required)
 define('JWT_AUTH_SECRET_KEY', 'replace-with-a-very-long-random-secret');
 ```

 Generate a secure key: `openssl rand -base64 64` or `php -r "echo bin2hex(random_bytes(64));"`.

 3) Ensure Authorization headers reach PHP. For Apache, add to `.htaccess`:

 ```apache
 RewriteEngine On
 RewriteCond %{HTTP:Authorization} .
 RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
 ```

 For Nginx, forward the `Authorization` header to PHP-FPM and configure CORS as needed.

 4) (Optional) Configure allowed CORS origins via the `optpress_jwt_allowed_origins` filter.

 API Endpoints (core)
 Base: `/wp-json/auth-jwt/v1`

 - POST `/token` — authenticate and receive `token` and `refresh_token`.
 - POST `/token/refresh` — exchange `refresh_token` for a new access token (rotates refresh token).
 - POST `/token/validate` — verify an access token.
 - POST `/logout` — revoke tokens / logout.
 - GET `/user/sessions` — list active sessions for the authenticated user.
 - POST `/user/sessions/revoke` — revoke all sessions for the authenticated user.

 Quick curl examples

 # Login and get tokens
 curl -s -X POST "https://your-site.com/wp-json/auth-jwt/v1/token" \
   -H "Content-Type: application/json" \
   -d '{"username":"Webmaster","password":"password","device_info":"iPhone 15"}'

 # Use access token (replace TOKEN)
 curl -s -X GET "https://your-site.com/wp-json/wp/v2/posts" \
   -H "Authorization: Bearer TOKEN"

 # Refresh token
 curl -s -X POST "https://your-site.com/wp-json/auth-jwt/v1/token/refresh" \
   -H "Content-Type: application/json" \
   -d '{"refresh_token":"REFRESH_TOKEN"}'

 Mobile integration (short)
 Store tokens securely (Keychain / Keystore / SecureStore). When a request returns 401, attempt a refresh with `/token/refresh` and retry the original request.

 Troubleshooting
 - "Key may not be empty": ensure `JWT_AUTH_SECRET_KEY` is defined in `wp-config.php` and hasn't changed.
 - 401 responses: confirm Authorization header format is `Bearer <token>` and token hasn't expired.
 - CORS issues: verify server sends `Access-Control-Allow-Origin` and forwards `Authorization` header.
 - Database issues: try deactivating/reactivating plugin to recreate tables; check DB user permissions.

 Configuration & filters
 - `optpress_jwt_allowed_origins` — filter to return an array of allowed origins for CORS.
 - `optpress_jwt_security_event` — action fired for security events (monitoring/logging).

 Support
 - Email: a.elfeda@gmail.com
 - Issues: open a GitHub issue in the repository

 License
 This plugin is licensed under GPL v2 or later.

 Author
 Abdessamad — https://github.com/elfedali

 Version: 1.2.0 — Last updated: March 19, 2026

      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }

  isAuthenticated() {
    return !!this.token;
  }
}

// Usage
const auth = new OptPressAuthService();

// Login
const result = await auth.login('username', 'password', 'iPhone 15 - MyApp v1.0');
if (result.success) {
  console.log('Logged in:', result.user);
}

// Make authenticated request
const response = await auth.makeAuthenticatedRequest(
  'https://yoursite.com/wp-json/wp/v2/posts'
);
const posts = await response.json();
```

### Swift/iOS Example

```swift
import Foundation

class OptPressAuthService {
    private let baseURL: String
    private var accessToken: String?
    private var refreshToken: String?
    
    init(baseURL: String) {
        self.baseURL = baseURL
        self.loadTokensFromKeychain()
    }
    
    func login(username: String, password: String, deviceInfo: String, completion: @escaping (Result<User, Error>) -> Void) {
        let url = URL(string: "\(baseURL)/token")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "username": username,
            "password": password,
            "device_info": deviceInfo
        ]
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            guard let data = data, error == nil else {
                completion(.failure(error!))
                return
            }
            
            // Parse response and save tokens
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let success = json["success"] as? Bool, success,
               let dataDict = json["data"] as? [String: Any],
               let token = dataDict["token"] as? String,
               let refresh = dataDict["refresh_token"] as? String {
                
                self?.accessToken = token
                self?.refreshToken = refresh
                self?.saveTokensToKeychain(accessToken: token, refreshToken: refresh)
                
                // Parse user
                // ... 
                
                completion(.success(user))
            } else {
                completion(.failure(NSError(domain: "AuthError", code: -1)))
            }
        }.resume()
    }
    
    private func saveTokensToKeychain(accessToken: String, refreshToken: String) {
        // Use Keychain Services
    }
    
    private func loadTokensFromKeychain() {
        // Load from Keychain Services
    }
}
```

### Flutter/Dart Example

```dart
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class OptPressAuthService {
  final String baseUrl;
  final _storage = FlutterSecureStorage();
  String? _accessToken;
  String? _refreshToken;

  OptPressAuthService(this.baseUrl);

  Future<Map<String, dynamic>> login(
    String username,
    String password, {
    String? deviceInfo,
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/token'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'password': password,
        'device_info': deviceInfo ?? '',
      }),
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      if (data['success']) {
        _accessToken = data['data']['token'];
        _refreshToken = data['data']['refresh_token'];
        
        await _storage.write(key: 'access_token', value: _accessToken);
        await _storage.write(key: 'refresh_token', value: _refreshToken);
        
        return {'success': true, 'user': data['data']['user']};
      }
    }
    
    return {'success': false, 'error': 'Authentication failed'};
  }

  Future<http.Response> makeAuthenticatedRequest(
    String url, {
    String method = 'GET',
    Map<String, dynamic>? body,
  }) async {
    if (_accessToken == null) {
      _accessToken = await _storage.read(key: 'access_token');
    }

    var response = await _sendRequest(url, method, body);

    // Handle token expiration
    if (response.statusCode == 401) {
      final refreshed = await refreshAccessToken();
      if (refreshed) {
        response = await _sendRequest(url, method, body);
      }
    }

    return response;
  }

  Future<http.Response> _sendRequest(
    String url,
    String method,
    Map<String, dynamic>? body,
  ) async {
    final headers = {
      'Authorization': 'Bearer $_accessToken',
      'Content-Type': 'application/json',
    };

    switch (method) {
      case 'POST':
        return http.post(Uri.parse(url), headers: headers, body: jsonEncode(body));
      case 'PUT':
        return http.put(Uri.parse(url), headers: headers, body: jsonEncode(body));
      case 'DELETE':
        return http.delete(Uri.parse(url), headers: headers);
      default:
        return http.get(Uri.parse(url), headers: headers);
    }
  }

  Future<bool> refreshAccessToken() async {
    if (_refreshToken == null) {
      _refreshToken = await _storage.read(key: 'refresh_token');
    }

    final response = await http.post(
      Uri.parse('$baseUrl/token/refresh'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh_token': _refreshToken}),
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      if (data['success']) {
        _accessToken = data['data']['token'];
        _refreshToken = data['data']['refresh_token'];
        
        await _storage.write(key: 'access_token', value: _accessToken);
        await _storage.write(key: 'refresh_token', value: _refreshToken);
        
        return true;
      }
    }

    return false;
  }

  Future<void> logout() async {
    if (_accessToken != null) {
      await http.post(
        Uri.parse('$baseUrl/logout'),
        headers: {'Authorization': 'Bearer $_accessToken'},
      );
    }

    _accessToken = null;
    _refreshToken = null;
    await _storage.deleteAll();
  }
}
```

## Security Features

### Token Management
- **Access Tokens**: Short-lived (configurable, default: 1 hour)
- **Refresh Tokens**: Long-lived (configurable, default: 30 days)
- **Token Rotation**: New refresh token on each refresh
- **SHA-256 Hashing**: Refresh tokens stored as hashes
- **Token Limiting**: Maximum 10 active refresh tokens per user

### Rate Limiting
- **Failed Login Protection**: Configurable maximum attempts
- **IP-Based Blocking**: Track attempts by IP address
- **Time Window**: 15-minute default lockout period
- **Automatic Reset**: Cleared on successful authentication

### Session Security
- **Device Tracking**: Unique identifier per device
- **IP Monitoring**: Track session IP addresses
- **Activity Timestamps**: Last activity tracking
- **Session Revocation**: Logout from all devices
- **Automatic Cleanup**: Daily removal of old sessions (30+ days)

### Audit Trail
- **Security Logging**: Database storage of critical events
- **Event Types**: authentication_failed, rate_limit_exceeded, token_validation_failed
- **90-Day Retention**: Automatic cleanup of old logs
- **WordPress Debug Log**: Integration with WP_DEBUG

## Configuration

### wp-config.php Settings

```php
// Required: JWT secret key (64+ characters recommended)
define('JWT_AUTH_SECRET_KEY', 'your-very-long-random-secret-key');

// Optional: Enable debug logging
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```

### Admin Settings (Settings  JWT Auth)

- **Access Token Expiry**: 300 - 86400 seconds (5 min - 24 hours)
- **Refresh Token Expiry**: 86400 - 7776000 seconds (1 - 90 days)
- **Max Login Attempts**: 3 - 20 attempts

### Programmatic Configuration

```php
// Filter allowed CORS origins
add_filter('optpress_jwt_allowed_origins', function($origins) {
    return ['https://yourapp.com', 'https://app.yoursite.com'];
});

// Listen to security events
add_action('optpress_jwt_security_event', function($event_type, $username, $details, $ip) {
    // Send to external monitoring service
    error_log("Security Event: $event_type from $ip");
}, 10, 4);
```

## Troubleshooting

### "Key may not be empty" Error
- Ensure `JWT_AUTH_SECRET_KEY` is defined in `wp-config.php`
- Key must be at least 1 character (recommended: 64+ characters)
- Check for typos in the constant name

### CORS Issues
- Verify `.htaccess` or nginx configuration
- Check that `Access-Control-Allow-Origin` header is present
- Ensure your app sends the `Origin` header

### Tokens Not Working
- Verify Authorization header format: `Bearer YOUR_TOKEN` (with space)
- Check that tokens haven't expired
- Ensure the secret key hasn't changed
- Verify user account is still active

### Rate Limiting False Positives
- Increase max login attempts in Settings  JWT Auth
- Check if multiple users share the same IP (office/NAT)
- Review security logs for patterns

### Database Issues
- Deactivate and reactivate the plugin to recreate tables
- Check MySQL user permissions
- Verify WordPress database prefix matches

### Debug Mode

Enable detailed logging:

```php
// In wp-config.php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```

Check logs at: `/wp-content/debug.log`

## Database Tables

The plugin creates four tables:

### 1. `wp_optpress_jwt_refresh_tokens`
Stores refresh tokens with metadata:
- `id`: Primary key
- `user_id`: WordPress user ID
- `token_hash`: SHA-256 hash of refresh token
- `expires_at`: Expiration timestamp
- `device_info`: Device description
- `ip_address`: Client IP
- `user_agent`: Browser/app identifier
- `is_revoked`: Revocation status
- `created_at`: Creation timestamp

### 2. `wp_optpress_jwt_sessions`
Tracks active user sessions:
- `id`: Primary key
- `user_id`: WordPress user ID
- `session_id`: Unique session identifier
- `device_info`: Device description
- `ip_address`: Client IP
- `last_activity`: Last request timestamp
- `created_at`: Session start timestamp

### 3. `wp_optpress_jwt_login_attempts`
Monitors failed login attempts for rate limiting:
- `id`: Primary key
- `username`: Attempted username
- `ip_address`: Client IP
- `attempt_time`: Attempt timestamp
- `user_agent`: Browser/app identifier

### 4. `wp_optpress_jwt_security_logs`
Audit trail of security events:
- `id`: Primary key
- `event_type`: Event category
- `username`: Related username
- `ip_address`: Client IP
- `user_agent`: Browser/app identifier
- `details`: Additional information
- `event_time`: Event timestamp

## Automatic Maintenance

The plugin includes automatic cleanup (runs daily):

- Expired refresh tokens (past expiration date)
- Revoked refresh tokens
- Old sessions (30+ days inactive)
- Old login attempts (7+ days old)
- Old security logs (90+ days old)

Schedule: Daily at server time (configured during activation)


## License

This plugin is licensed under GPL v2 or later.

## Author

**Abdessamad**  
Website: [https://github.com/elfedali](https://github.com/elfedali)

## Support

For issues, questions, or feature requests:
- GitHub Issues: [Create an issue](#)
- Documentation: [Full API docs](#)
- Email: support@optpress.com

---

**Version**: 1.2.0  
**Last Updated**: March 19, 2026  
**Requires WordPress**: 5.0+  
**Requires PHP**: 7.4+  
**Tested up to**: WordPress 6.4  
**License**: GPL v2 or later
