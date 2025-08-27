<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'EMA_LOGIN_ATTEMPTS_LIMIT', 5 );
define( 'EMA_LOGIN_LOCKOUT_DURATION', 15 * MINUTE_IN_SECONDS );

function ema_hardening_apply_rules() {
	add_action( 'send_headers', 'ema_hardening_add_security_headers' );
	add_filter( 'xmlrpc_enabled', '__return_false' );
	add_filter( 'authenticate', 'ema_hardening_check_login_lockout', 30, 1 );
	remove_action( 'wp_head', 'wp_generator' );
	add_filter( 'the_generator', '__return_empty_string' );
	add_filter( 'rest_authentication_errors', 'ema_hardening_protect_rest_api' );
}

function ema_hardening_add_security_headers() {
	if ( headers_sent() ) return;
	header( 'X-Frame-Options: SAMEORIGIN' ); header( 'X-Content-Type-Options: nosniff' ); header( 'X-XSS-Protection: 1; mode=block' ); header( 'Referrer-Policy: strict-origin-when-cross-origin' );
}

function ema_hardening_check_login_lockout( $user ) {
	$ip = ema_hardening_get_user_ip(); $transient_key = 'ema_login_failed_' . $ip;
	if ( (int) get_transient( $transient_key ) >= EMA_LOGIN_ATTEMPTS_LIMIT ) {
		return new WP_Error( 'too_many_retries', '<strong>ERRO</strong>: Você excedeu o número máximo de tentativas de login.' );
	}
	return $user;
}

function ema_hardening_protect_rest_api( $result ) {
	if ( ! empty( $result ) || is_user_logged_in() ) return $result;
	$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? trailingslashit( $_SERVER['REQUEST_URI'] ) : '';
	if ( strpos( $request_uri, '/wp/v2/users/' ) !== false ) {
		return new WP_Error( 'rest_cannot_access', 'O acesso à lista de usuários é restrito.', [ 'status' => rest_authorization_required_code() ] );
	}
	return $result;
}