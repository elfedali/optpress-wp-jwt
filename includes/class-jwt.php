<?php
/**
 * JSON Web Token implementation for PHP 7+
 * Based on RFC 7519
 */

class JWT {
    
    /**
     * Supported algorithms
     */
    public static $supported_algs = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
    ];
    
    /**
     * Encode a PHP object into a JSON Web Token (JWT)
     *
     * @param array $payload PHP array to be encoded
     * @param string $key The secret key
     * @param string $alg The signing algorithm
     * @return string A signed JWT
     */
    public static function encode($payload, $key, $alg = 'HS256') {
        $header = ['typ' => 'JWT', 'alg' => $alg];
        
        $segments = [];
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        
        $signing_input = implode('.', $segments);
        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);
        
        return implode('.', $segments);
    }
    
    /**
     * Decode a JSON Web Token (JWT)
     *
     * @param string $jwt The JWT token
     * @param string $key The secret key
     * @param array $allowed_algs List of supported algorithms
     * @return object The JWT's payload as a PHP object
     * @throws Exception
     */
    public static function decode($jwt, $key, $allowed_algs = []) {
        $timestamp = time();
        
        if (empty($key)) {
            throw new Exception('Key may not be empty');
        }
        
        $tks = explode('.', $jwt);
        
        if (count($tks) !== 3) {
            throw new Exception('Wrong number of segments');
        }
        
        list($headb64, $bodyb64, $cryptob64) = $tks;
        
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new Exception('Invalid header encoding');
        }
        
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new Exception('Invalid claims encoding');
        }
        
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new Exception('Invalid signature encoding');
        }
        
        if (empty($header->alg)) {
            throw new Exception('Empty algorithm');
        }
        
        if (empty(static::$supported_algs[$header->alg])) {
            throw new Exception('Algorithm not supported');
        }
        
        if (!in_array($header->alg, $allowed_algs)) {
            throw new Exception('Algorithm not allowed');
        }
        
        // Check signature
        if (!static::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new Exception('Signature verification failed');
        }
        
        // Check if the token is expired
        if (isset($payload->exp) && $timestamp >= $payload->exp) {
            throw new Exception('Expired token');
        }
        
        // Check if the token is being used before it's valid
        if (isset($payload->nbf) && $payload->nbf > $timestamp) {
            throw new Exception('Cannot handle token prior to ' . date('Y-m-d H:i:s', $payload->nbf));
        }
        
        // Check if the token was issued in the future
        if (isset($payload->iat) && $payload->iat > $timestamp) {
            throw new Exception('Cannot handle token with future issue date');
        }
        
        return $payload;
    }
    
    /**
     * Sign a string with a given key and algorithm
     *
     * @param string $msg The message to sign
     * @param string $key The secret key
     * @param string $alg The signing algorithm
     * @return string An encrypted message
     * @throws Exception
     */
    public static function sign($msg, $key, $alg = 'HS256') {
        if (empty(static::$supported_algs[$alg])) {
            throw new Exception('Algorithm not supported');
        }
        
        list($function, $algorithm) = static::$supported_algs[$alg];
        
        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $msg, $key, true);
            default:
                throw new Exception("Algorithm not supported");
        }
    }
    
    /**
     * Verify a signature with the message, key and method
     *
     * @param string $msg The original message
     * @param string $signature The original signature
     * @param string $key The secret key
     * @param string $alg The algorithm
     * @return boolean
     */
    private static function verify($msg, $signature, $key, $alg) {
        if (empty(static::$supported_algs[$alg])) {
            throw new Exception('Algorithm not supported');
        }
        
        list($function, $algorithm) = static::$supported_algs[$alg];
        
        switch($function) {
            case 'hash_hmac':
                $hash = hash_hmac($algorithm, $msg, $key, true);
                return static::constantTimeEquals($hash, $signature);
            default:
                throw new Exception("Algorithm not supported");
        }
    }
    
    /**
     * Decode a JSON string into a PHP array
     *
     * @param string $input JSON string
     * @return array
     * @throws Exception
     */
    public static function jsonDecode($input) {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }
        
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new Exception('Null result with non-null input');
        }
        
        return $obj;
    }
    
    /**
     * Encode a PHP array into a JSON string
     *
     * @param array $input A PHP array
     * @return string JSON representation of the PHP array
     * @throws Exception
     */
    public static function jsonEncode($input) {
        $json = json_encode($input);
        
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new Exception('Null result with non-null input');
        }
        
        return $json;
    }
    
    /**
     * Decode a string with URL-safe Base64
     *
     * @param string $input A Base64 encoded string
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input) {
        $remainder = strlen($input) % 4;
        
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        
        return base64_decode(strtr($input, '-_', '+/'));
    }
    
    /**
     * Encode a string with URL-safe Base64
     *
     * @param string $input The string you want encoded
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
    
    /**
     * Helper method to create a JSON error
     *
     * @param int $errno An error number from json_last_error()
     * @throws Exception
     */
    private static function handleJsonError($errno) {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters, possibly incorrectly encoded'
        ];
        
        throw new Exception(
            isset($messages[$errno]) ? $messages[$errno] : 'Unknown JSON error: ' . $errno
        );
    }
    
    /**
     * Compare two strings using the same time whether they're equal or not
     *
     * @param string $safe The internal (safe) value to be checked
     * @param string $user The user submitted (unsafe) value
     * @return boolean True if the two strings are identical
     */
    private static function constantTimeEquals($safe, $user) {
        if (function_exists('hash_equals')) {
            return hash_equals($safe, $user);
        }
        
        $safeLen = strlen($safe);
        $userLen = strlen($user);
        
        if ($userLen !== $safeLen) {
            return false;
        }
        
        $result = 0;
        
        for ($i = 0; $i < $userLen; $i++) {
            $result |= (ord($safe[$i]) ^ ord($user[$i]));
        }
        
        // They are only identical strings if $result is exactly 0...
        return $result === 0;
    }
}
