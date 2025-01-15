<?php
// includes/class-cookie-consent.php

if (!defined('ABSPATH')) {
    exit;
}

class CookieConsent {
    private static $cookie_set = null;
    
    public function __construct() {
        // Only add hooks if cookie is not set
        if (self::$cookie_set === null) {
            self::$cookie_set = isset($_COOKIE['cookie_consent']);
        }
        
        if (!self::$cookie_set) {
            add_action('wp_footer', array($this, 'render_cookie_banner'));
            add_action('rest_api_init', array($this, 'register_cookie_consent_endpoint'));
        }
    }

    public function render_cookie_banner() {
        $cookie_notice_text = get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.');
        ?>
        <style>
            .cookie-consent-banner {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background: #f1f1f1;
                padding: 20px;
                text-align: center;
                box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
                z-index: 9999;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            }
            .cookie-consent-banner p {
                margin: 0 0 15px 0;
                color: #333;
                font-size: 14px;
            }
            .cookie-consent-buttons {
                display: flex;
                justify-content: center;
                gap: 10px;
            }
            .cookie-consent-button {
                padding: 8px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 500;
                font-size: 14px;
                transition: opacity 0.2s ease;
            }
            .cookie-consent-button:hover {
                opacity: 0.9;
            }
            .cookie-accept {
                background: #4CAF50;
                color: white;
            }
            .cookie-reject {
                background: #f44336;
                color: white;
            }
        </style>
        <div class="cookie-consent-banner">
            <p><?php echo esc_html($cookie_notice_text); ?></p>
            <div class="cookie-consent-buttons">
                <button class="cookie-consent-button cookie-accept" onclick="handleCookieConsent('accept')">Accept</button>
                <button class="cookie-consent-button cookie-reject" onclick="handleCookieConsent('reject')">Reject</button>
            </div>
        </div>

        <script>
        function handleCookieConsent(action) {
            fetch('<?php echo esc_url(rest_url('security-plugin/v1/cookie-consent')); ?>', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': '<?php echo wp_create_nonce('wp_rest'); ?>'
                },
                body: JSON.stringify({
                    consent: action === 'accept'
                })
            }).then(() => {
                document.querySelector('.cookie-consent-banner').style.display = 'none';
            }).catch(error => {
                console.error('Error:', error);
            });
        }
        </script>
        <?php
    }

    public function register_cookie_consent_endpoint() {
        register_rest_route('security-plugin/v1', '/cookie-consent', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_cookie_consent'),
            'permission_callback' => '__return_true'
        ));
    }

    public function handle_cookie_consent($request) {
        $consent = $request->get_param('consent');
        $value = $consent ? 'accepted' : 'rejected';
        setcookie('cookie_consent', $value, time() + (365 * 24 * 60 * 60), '/', '', true, true);
        return new WP_REST_Response(array(
            'status' => 'success',
            'consent' => $value
        ), 200);
    }
}
