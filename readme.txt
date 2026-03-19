=== OptPress JWT ===
Contributors: elfedali
Tags: jwt, authentication, rest-api, mobile, security
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure JWT authentication for WordPress REST API with refresh tokens, session management, rate limiting, and mobile app support.

== Description ==

OptPress JWT adds JWT (JSON Web Token) authentication to your WordPress site's REST API. It is designed for headless WordPress setups and mobile apps that need stateless, token-based authentication.

**Core features:**

* Short-lived access tokens (configurable, default 1 hour)
* Refresh tokens with automatic rotation (stored as SHA-256 hashes)
* Per-device session tracking and management
* IP-based rate limiting and failed-login protection
* Comprehensive security audit log
* Admin settings page with system status
* Full CORS support

**REST API endpoints** (base: `/wp-json/auth-jwt/v1`):

* `POST /token` — Login, returns access + refresh token
* `POST /token/refresh` — Exchange refresh token for a new access token
* `POST /token/validate` — Validate an access token
* `POST /logout` — Revoke tokens / logout
* `GET /user/sessions` — List active sessions
* `POST /user/sessions/revoke` — Revoke all sessions

**Privacy:** This plugin does not transmit any user data to external servers. All tokens and session data are stored locally in your WordPress database.

== Installation ==

1. Upload the `optpress-wp-jwt` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** screen in WordPress.
3. Add your JWT secret key to `wp-config.php`:

`define('JWT_AUTH_SECRET_KEY', 'your-64-character-random-secret-here');`

Generate a secure key with: `openssl rand -base64 64`

4. For Apache, add to `.htaccess` to pass the Authorization header to PHP:

`RewriteEngine On`
`RewriteCond %{HTTP:Authorization} .`
`RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]`

5. Go to **Settings > JWT Auth** to configure token expiry and rate limiting.

== Frequently Asked Questions ==

= Why do I get "Key may not be empty"? =

Ensure `JWT_AUTH_SECRET_KEY` is defined in your `wp-config.php` file and contains at least one character. A minimum of 64 random characters is strongly recommended.

= How do I use the access token? =

Include it as a Bearer token in the `Authorization` header of your requests:

`Authorization: Bearer YOUR_ACCESS_TOKEN`

= What happens when the access token expires? =

Use the `POST /token/refresh` endpoint with your `refresh_token` to obtain a new access token without requiring the user to log in again.

= Is this plugin compatible with the WP REST API? =

Yes. Once authenticated, you can use the access token to make any WP REST API request that requires authentication.

= Does this work with Nginx? =

Yes. Ensure your Nginx configuration forwards the `Authorization` header to PHP-FPM. Refer to the plugin README for example configuration.

= How do I enable CORS for my app? =

Use the `optpress_jwt_allowed_origins` filter to specify allowed origins:

`add_filter('optpress_jwt_allowed_origins', function($origins) {`
`    return ['https://yourapp.com'];`
`});`

== Screenshots ==

1. Admin settings page — configure token expiry and rate limiting.
2. System status — view active sessions, token counts, and security logs.

== Changelog ==

= 1.2.0 — March 19, 2026 =
* Bump version and update metadata.
* Added Last Updated header.
* Added LICENSE.txt.
* Improved README.

= 1.0.0 — November 24, 2025 =
* Initial release.
* JWT token generation and validation.
* Refresh tokens with rotation.
* Session management per device.
* Rate limiting and security logging.
* Admin settings page.
* CORS support.

== Upgrade Notice ==

= 1.2.0 =
Maintenance release. No database changes.

== Privacy Policy ==

OptPress JWT does not collect, transmit, or share any personal data with external services. All session data, tokens, and logs are stored in your local WordPress database. You can purge this data by deactivating and deleting the plugin.
