<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

$cookie_notice_text = get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.');
?>
<div id="cookie-consent-banner" style="position: fixed; bottom: 0; left: 0; right: 0; background: #f1f1f1; padding: 1rem; text-align: center; box-shadow: 0 -2px 10px rgba(0,0,0,0.1); z-index: 9999;">
    <p style="margin: 0 0 1rem 0;"><?php echo esc_html($cookie_notice_text); ?></p>
    <button onclick="acceptCookies()" style="background: #0073aa; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;">Accept</button>
</div>

<script>
function acceptCookies() {
    // Send acceptance to REST API endpoint
    fetch('<?php echo esc_url(rest_url('security-plugin/v1/cookie-consent')); ?>', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-WP-Nonce': '<?php echo wp_create_nonce('wp_rest'); ?>'
        },
        body: JSON.stringify({
            consent: true
        })
    }).then(() => {
        document.getElementById('cookie-consent-banner').style.display = 'none';
    });
}
</script>