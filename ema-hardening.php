<?php
/**
 * Plugin Name:         EMA Hardening Security
 * Description:         Segurança completa para WordPress: hardening, firewall, scanner de arquivos e log de atividades.
 * Version:             1.3.1
 * Author:              Eberton M. Alvares
 * Author URI:          
 * License:             GPL2
 * License URI:         https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:         ema-hardening
 * Domain Path:         /languages
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'EMA_HARDENING_VERSION', '1.3.1' );
define( 'EMA_HARDENING_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

function ema_hardening_simple_waf() {
	if ( is_admin() ) { return; }
	$blocked_patterns = [ '/\b(union|select|insert|concat|drop|update)\b/i', '/\/\*.*\*\/|--|#/', '/<script\b[^>]*>.*<\/script>/is', '/\b(on[a-z]+|javascript:)\s*=/i', '/\.\.\//', ];
	if ( function_exists( 'ema_hardening_get_user_ip' ) && function_exists( 'ema_hardening_block_ip' ) ) {
		$input_data = array_merge( $_GET, $_POST );
		foreach ( $input_data as $key => $value ) {
			if ( is_string( $value ) ) {
				foreach ( $blocked_patterns as $pattern ) {
					if ( preg_match( $pattern, $value ) ) {
						$ip = ema_hardening_get_user_ip();
						ema_hardening_block_ip( $ip, 'WAF: Malicious Pattern' );
						wp_die( 'Forbidden', 'Forbidden', [ 'response' => 403 ] );
					}
				}
			}
		}
	}
}
add_action( 'plugins_loaded', 'ema_hardening_simple_waf', 1 );

function ema_hardening_load_files() {
	require_once EMA_HARDENING_PLUGIN_DIR . 'includes/ema-anti-spam.php';
	require_once EMA_HARDENING_PLUGIN_DIR . 'includes/ema-hardening-functions.php';
	require_once EMA_HARDENING_PLUGIN_DIR . 'includes/ema-activity-logger.php';
	require_once EMA_HARDENING_PLUGIN_DIR . 'admin/ema-admin-page.php';
	require_once EMA_HARDENING_PLUGIN_DIR . 'admin/ema-scanner-page.php';
	require_once EMA_HARDENING_PLUGIN_DIR . 'admin/ema-logs-page.php';
}
add_action( 'plugins_loaded', 'ema_hardening_load_files', 5 );

add_action( 'plugins_loaded', 'ema_hardening_apply_rules', 10 );

function ema_hardening_load_textdomain() {
	load_plugin_textdomain( 'ema-hardening', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
}
add_action( 'plugins_loaded', 'ema_hardening_load_textdomain' );

register_activation_hook( __FILE__, 'ema_hardening_activate' );
function ema_hardening_activate() { ema_hardening_create_custom_tables(); }

function ema_hardening_create_custom_tables() {
	global $wpdb; require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$charset_collate = $wpdb->get_charset_collate();
	$table_ips = $wpdb->prefix . 'ema_hardening_blocked_ips';
	$sql_ips   = "CREATE TABLE $table_ips ( id bigint(20) NOT NULL AUTO_INCREMENT, ip varchar(100) NOT NULL, blocked_until datetime NOT NULL, reason varchar(255) NOT NULL, PRIMARY KEY  (id), UNIQUE KEY ip (ip) ) $charset_collate;";
	dbDelta( $sql_ips );
	$table_logs = $wpdb->prefix . 'ema_hardening_logs';
	$sql_logs   = "CREATE TABLE $table_logs ( id bigint(20) NOT NULL AUTO_INCREMENT, user_id bigint(20) UNSIGNED NOT NULL, ip_address varchar(100) NOT NULL, event_type varchar(50) NOT NULL, details text NOT NULL, event_time datetime NOT NULL, PRIMARY KEY  (id), KEY event_type (event_type), KEY user_id (user_id) ) $charset_collate;";
	dbDelta( $sql_logs );
}