<?php
/*
Plugin Name: Custom Security Plugin
Description: Security plugin with URL exclusion, blocking, and comprehensive security features
Version: 1.2
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load components
require_once plugin_dir_path(__FILE__) . 'includes/class-waf.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-headers.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-consent.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sanitization.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-feature-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-settings.php';

class CustomSecurityPlugin {
    private $waf;
    private $headers;
    private $cookie_consent;
    private $sanitization;
    private $feature_manager;
    private $settings;

    public function __construct() {
        // Only load components when needed
        add_action('plugins_loaded', array($this, 'init_components'), 1);
    }

    public function init_components() {
        // Initialize components only when needed
        if (!is_admin()) {
            $this->headers = new SecurityHeaders();
            add_action('init', array($this->headers, 'add_security_headers'));
            
            if (!isset($_COOKIE['cookie_consent'])) {
                $this->cookie_consent = new CookieConsent();
            }
            
            $this->waf = new SecurityWAF();
        }

        // Always load these components
        $this->sanitization = new SecuritySanitization();
        $this->feature_manager = new FeatureManager();
        
        // Load settings only in admin
        if (is_admin()) {
            $this->settings = new SecuritySettings();
            add_action('admin_menu', array($this->settings, 'add_admin_menu'));
            add_action('admin_init', array($this->settings, 'register_settings'));
        }
        
        add_action('plugins_loaded', array($this->feature_manager, 'init'));
    }
}

// Initialize the plugin
$custom_security_plugin = new CustomSecurityPlugin();
