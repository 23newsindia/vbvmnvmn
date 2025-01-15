<?php
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

        if (isset($_POST['save_settings']) && check_admin_referer('security_settings_nonce', 'security_nonce')) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
        }

        // Get all options with default values
        $options = array(
            'excluded_paths' => get_option('security_excluded_paths', ''),
            'blocked_patterns' => get_option('security_blocked_patterns', ''),
            'excluded_php_paths' => get_option('security_excluded_php_paths', ''),
            'remove_feeds' => get_option('security_remove_feeds', false),
            'remove_oembed' => get_option('security_remove_oembed', false),
            'remove_pingback' => get_option('security_remove_pingback', false),
            'remove_wp_json' => get_option('security_remove_wp_json', false),
            'remove_rsd' => get_option('security_remove_rsd', false),
            'remove_wp_generator' => get_option('security_remove_wp_generator', false),
            'allow_adsense' => get_option('security_allow_adsense', false),
            'allow_youtube' => get_option('security_allow_youtube', false),
            'allow_twitter' => get_option('security_allow_twitter', false),
            'remove_query_strings' => get_option('security_remove_query_strings', false),
            'cookie_notice_text' => get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.'),
            'enable_xss' => get_option('security_enable_xss', true),
            'enable_waf' => get_option('security_enable_waf', true),
            'waf_request_limit' => get_option('security_waf_request_limit', 100),
            'waf_blacklist_threshold' => get_option('security_waf_blacklist_threshold', 5)
        );
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>
            <form method="post" action="">
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
                        <th>Query String Settings</th>
                        <td>
                            <label>
                                <input type="checkbox" name="remove_query_strings" value="1" <?php checked($options['remove_query_strings']); ?>>
                                Remove Query Strings from URLs
                            </label>
                            <p class="description">Automatically removes query parameters from URLs (e.g., ?anything)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Excluded Paths</th>
                        <td>
                            <textarea name="excluded_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_paths']); ?></textarea>
                            <p class="description">Enter one path per line (e.g., /register/?action=check_email). These paths will keep their query strings.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Third-party Services</th>
                        <td>
                            <label>
                                <input type="checkbox" name="allow_adsense" value="1" <?php checked($options['allow_adsense']); ?>>
                                Allow Google AdSense
                            </label><br>
                            <label>
                                <input type="checkbox" name="allow_youtube" value="1" <?php checked($options['allow_youtube']); ?>>
                                Allow YouTube Embeds
                            </label><br>
                            <label>
                                <input type="checkbox" name="allow_twitter" value="1" <?php checked($options['allow_twitter']); ?>>
                                Allow Twitter Embeds
                            </label>
                            <p class="description">Enable these options to allow specific third-party services through the Content Security Policy</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Security Features</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enable_xss" value="1" <?php checked($options['enable_xss']); ?>>
                                Enable XSS Protection
                            </label>
                            <p class="description">Controls Content Security Policy and other XSS protection features</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Cookie Notice Text</th>
                        <td>
                            <textarea name="cookie_notice_text" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['cookie_notice_text']); ?></textarea>
                            <p class="description">Customize the cookie consent notice text</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>WAF Settings</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enable_waf" value="1" <?php checked($options['enable_waf']); ?>>
                                Enable Web Application Firewall
                            </label>
                            <p class="description">Protects against common web attacks including SQL injection, XSS, and file inclusion attempts</p>
                            
                            <br><br>
                            <label>
                                Request Limit per Minute:
                                <input type="number" name="waf_request_limit" value="<?php echo esc_attr($options['waf_request_limit']); ?>" min="10" max="1000">
                            </label>
                            
                            <br><br>
                            <label>
                                Blacklist Threshold (violations/24h):
                                <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr($options['waf_blacklist_threshold']); ?>" min="1" max="100">
                            </label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>PHP Access Exclusions</th>
                        <td>
                            <textarea name="excluded_php_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_php_paths']); ?></textarea>
                            <p class="description">Enter paths to allow PHP access (e.g., wp-admin, wp-login.php)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Blocked Patterns</th>
                        <td>
                            <textarea name="blocked_patterns" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['blocked_patterns']); ?></textarea>
                            <p class="description">Enter one pattern per line (e.g., %3C, %3E)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Remove Features</th>
                        <td>
                            <label>
                                <input type="checkbox" name="remove_feeds" value="1" <?php checked($options['remove_feeds']); ?>>
                                Remove RSS Feeds
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_oembed" value="1" <?php checked($options['remove_oembed']); ?>>
                                Remove oEmbed Links
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_pingback" value="1" <?php checked($options['remove_pingback']); ?>>
                                Remove Pingback and Disable XMLRPC
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_wp_json" value="1" <?php checked($options['remove_wp_json']); ?>>
                                Remove WP REST API Links (wp-json)
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_rsd" value="1" <?php checked($options['remove_rsd']); ?>>
                                Remove RSD Link
                            </label><br>
                            <label>
                                <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($options['remove_wp_generator']); ?>>
                                Remove WordPress Generator Meta Tag
                            </label>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <input type="submit" name="save_settings" class="button button-primary" value="Save Settings">
                </p>
            </form>
        </div>
        <?php
    }

     private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Sanitize excluded paths while preserving query strings
        $excluded_paths = isset($_POST['excluded_paths']) ? trim($_POST['excluded_paths']) : '';
        $paths = explode("\n", $excluded_paths);
        $sanitized_paths = array();
        
        foreach ($paths as $path) {
            $path = trim($path);
            if (!empty($path)) {
                // Parse the URL to preserve query strings properly
                $parsed = parse_url($path);
                $sanitized_path = '';
                
                // Add path component
                if (isset($parsed['path'])) {
                    $sanitized_path .= preg_replace('/[^a-zA-Z0-9\/_\-]/', '', $parsed['path']);
                }
                
                // Add query string if exists
                if (isset($parsed['query'])) {
                    $sanitized_path .= '?' . preg_replace('/[^a-zA-Z0-9=&_\-]/', '', $parsed['query']);
                }
                
                if (!empty($sanitized_path)) {
                    $sanitized_paths[] = $sanitized_path;
                }
            }
        }
        
        $sanitized_excluded_paths = implode("\n", array_unique($sanitized_paths));

        // Save all settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', $sanitized_excluded_paths);
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
        update_option('security_remove_query_strings', isset($_POST['remove_query_strings']));
        update_option('security_allow_adsense', isset($_POST['allow_adsense']));
        update_option('security_allow_youtube', isset($_POST['allow_youtube']));
        update_option('security_allow_twitter', isset($_POST['allow_twitter']));
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
        register_setting('security_settings', 'security_remove_query_strings');
        register_setting('security_settings', 'security_remove_wp_json');
        register_setting('security_settings', 'security_remove_rsd');
        register_setting('security_settings', 'security_remove_wp_generator');
        register_setting('security_settings', 'security_waf_request_limit');
        register_setting('security_settings', 'security_waf_blacklist_threshold');
        register_setting('security_settings', 'security_allow_adsense');
        register_setting('security_settings', 'security_allow_youtube');
        register_setting('security_settings', 'security_allow_twitter');
    }
}