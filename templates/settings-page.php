<?php
// includes/class-settings.php
class SecuritySettings {
    public function add_admin_menu() {
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings',
            array($this, 'render_settings_page'),
            'dashicons-shield'
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['save_settings'])) {
            $this->save_settings();
        }

        // Get all options
        $excluded_paths = get_option('security_excluded_paths', '');
        $blocked_patterns = get_option('security_blocked_patterns', '');
        $excluded_php_paths = get_option('security_excluded_php_paths', '');
        $remove_feeds = get_option('security_remove_feeds', false);
        $remove_oembed = get_option('security_remove_oembed', false);
        $remove_pingback = get_option('security_remove_pingback', false);
        $remove_wp_json = get_option('security_remove_wp_json', false);
        $remove_rsd = get_option('security_remove_rsd', false);
        $remove_wp_generator = get_option('security_remove_wp_generator', false);
        $cookie_notice_text = get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.');
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>
            <form method="post">
                <?php wp_nonce_field('security_settings_nonce', 'security_nonce'); ?>
                <table class="form-table">
                    <tr>
                        <th>XSS Protection</th>
                        <td>
                            <p class="description">XSS protection is enabled by default and includes:</p>
                            <ul style="list-style-type: disc; margin-left: 20px;">
                                <li>Content Security Policy (CSP) headers</li>
                                <li>Input sanitization for comments and posts</li>
                                <li>Secure file upload handling</li>
                                <li>URL parameter sanitization</li>
                            </ul>
                        </td>
                    </tr>
                    <tr>
                        <th>Security Features</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enable_xss" value="1" <?php checked(get_option('security_enable_xss', true)); ?>>
                                Enable XSS Protection
                            </label>
                            <p class="description">Controls Content Security Policy and other XSS protection features</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Cookie Notice Text</th>
                        <td>
                            <textarea name="cookie_notice_text" rows="3" cols="50"><?php echo esc_textarea($cookie_notice_text); ?></textarea>
                            <p class="description">Customize the cookie consent notice text</p>
                        </td>
                    </tr>
                    <tr>
                        <th>WAF Settings</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enable_waf" value="1" <?php checked(get_option('security_enable_waf', true)); ?>>
                                Enable Web Application Firewall
                            </label>
                            <p class="description">Protects against common web attacks including SQL injection, XSS, and file inclusion attempts</p>
                            
                            <br><br>
                            <label>
                                Request Limit per Minute:
                                <input type="number" name="waf_request_limit" value="<?php echo esc_attr(get_option('security_waf_request_limit', 100)); ?>" min="10" max="1000">
                            </label>
                            
                            <br><br>
                            <label>
                                Blacklist Threshold (violations/24h):
                                <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr(get_option('security_waf_blacklist_threshold', 5)); ?>" min="1" max="100">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Excluded Paths</th>
                        <td>
                            <textarea name="excluded_paths" rows="5" cols="50"><?php echo esc_textarea($excluded_paths); ?></textarea>
                            <p class="description">Enter one path per line (e.g., wp-admin, wp-login.php)</p>
                        </td>
                    </tr>
                    <tr>
                        <th>PHP Access Exclusions</th>
                        <td>
                            <textarea name="excluded_php_paths" rows="5" cols="50"><?php echo esc_textarea($excluded_php_paths); ?></textarea>
                            <p class="description">Enter paths to allow PHP access (e.g., wp-admin, wp-login.php)</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Blocked Patterns</th>
                        <td>
                            <textarea name="blocked_patterns" rows="5" cols="50"><?php echo esc_textarea($blocked_patterns); ?></textarea>
                            <p class="description">Enter one pattern per line (e.g., %3C, %3E)</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Remove Features</th>
                        <td>
                            <label>
                                <input type="checkbox" name="remove_feeds" value="1" <?php checked($remove_feeds); ?>>
                                Remove RSS Feeds
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_oembed" value="1" <?php checked($remove_oembed); ?>>
                                Remove oEmbed Links
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_pingback" value="1" <?php checked($remove_pingback); ?>>
                                Remove Pingback and Disable XMLRPC
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_wp_json" value="1" <?php checked($remove_wp_json); ?>>
                                Remove WP REST API Links (wp-json)
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_rsd" value="1" <?php checked($remove_rsd); ?>>
                                Remove RSD Link
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($remove_wp_generator); ?>>
                                Remove WordPress Generator Meta Tag
                            </label>
                        </td>
                    </tr>
                </table>
                <p>
                    <input type="submit" name="save_settings" class="button button-primary" value="Save Settings">
                </p>
            </form>
        </div>
        <?php
    }

    public function register_settings() {
        register_setting('security_settings', 'security_enable_waf');
        register_setting('security_settings', 'security_enable_xss');
        register_setting('security_settings', 'security_cookie_notice_text');
        register_setting('security_settings', 'security_excluded_paths');
        register_setting('security_settings', 'security_blocked_patterns');
        register_setting('security_settings', 'security_excluded_php_paths');
        register_setting('security_settings', 'security_remove_feeds');
        register_setting('security_settings', 'security_remove_oembed');
        register_setting('security_settings', 'security_remove_pingback');
        register_setting('security_settings', 'security_remove_wp_json');
        register_setting('security_settings', 'security_remove_rsd');
        register_setting('security_settings', 'security_remove_wp_generator');
        register_setting('security_settings', 'security_waf_request_limit');
        register_setting('security_settings', 'security_waf_blacklist_threshold');
    }

    private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Verify nonce
        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Save all settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', sanitize_textarea_field($_POST['excluded_paths']));
        update_option('security_blocked_patterns', sanitize_textarea_field($_POST['blocked_patterns']));
        update_option('security_excluded_php_paths', sanitize_textarea_field($_POST['excluded_php_paths']));
        update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
    }
}