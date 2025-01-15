<?php

// includes/class-sanitization.php
class SecuritySanitization {
    public function sanitize_comment_content($content) {
        $allowed_tags = array(
            'a' => array('href' => array(), 'title' => array()),
            'b' => array(),
            'em' => array(),
            'strong' => array(),
            'p' => array()
        );

        $content = wp_kses($content, $allowed_tags);
        return $this->remove_null_bytes($content);
    }

    public function sanitize_post_content($content) {
        $allowed_html = wp_kses_allowed_html('post');
        $content = wp_kses($content, $allowed_html);
        return $this->remove_null_bytes($content);
    }

    public function sanitize_upload_filename($filename) {
        $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
        return strtolower($filename);
    }

    public function sanitize_url($url) {
        $url = $this->remove_null_bytes($url);
        $url = preg_replace('/javascript:/i', '', $url);
        $url = preg_replace('/data:/i', '', $url);
        return $url;
    }

    private function remove_null_bytes($content) {
        return str_replace(chr(0), '', $content);
    }
}
