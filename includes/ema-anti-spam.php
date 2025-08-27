<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'EMA_SPAM_BLOCK_DURATION', 7 * DAY_IN_SECONDS );
add_filter( 'preprocess_comment', 'ema_hardening_check_comment_for_spam' );
add_action( 'comment_form_after_fields', 'ema_hardening_add_honeypot_field' );
add_action( 'comment_form_logged_in_after', 'ema_hardening_add_honeypot_field' );

function ema_hardening_add_honeypot_field() {
	echo '<p class="comment-form-honeypot" style="display:none !important;" aria-hidden="true"><label for="ema_hp_field">' . esc_html__( 'Leave this field empty', 'ema-hardening' ) . '</label><input type="text" name="ema_hp_field" id="ema_hp_field" value="" autocomplete="off" tabindex="-1" /></p>';
}

function ema_hardening_check_comment_for_spam( $commentdata ) {
	$user_ip = ema_hardening_get_user_ip();
	if ( ema_hardening_is_ip_blocked( $user_ip ) ) { wp_die( 'Seu endereço de IP foi sinalizado.', 'Erro', [ 'response' => 403 ] ); }
	if ( isset( $_POST['ema_hp_field'] ) && ! empty( $_POST['ema_hp_field'] ) ) {
		ema_hardening_block_ip( $user_ip, 'Honeypot Triggered' );
		wp_die( 'O comentário não pôde ser publicado.', 'Erro', [ 'response' => 403 ] );
	}
	return $commentdata;
}

function ema_hardening_get_user_ip() {
	$ip_keys = [ 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' ];
	foreach ( $ip_keys as $key ) {
		if ( ! empty( $_SERVER[ $key ] ) ) {
			$ips = explode( ',', $_SERVER[ $key ] ); $ip = trim( end( $ips ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) { return $ip; }
		}
	}
	return '0.0.0.0';
}

function ema_hardening_block_ip( $ip, $reason, $duration = EMA_SPAM_BLOCK_DURATION ) {
	global $wpdb; if ( empty( $ip ) || $ip === '0.0.0.0' ) return;
	$table_name = $wpdb->prefix . 'ema_hardening_blocked_ips';
	$blocked_until = gmdate( 'Y-m-d H:i:s', time() + $duration );
	$wpdb->replace( $table_name, [ 'ip' => $ip, 'blocked_until' => $blocked_until, 'reason' => $reason ], [ '%s', '%s', '%s' ] );
}

function ema_hardening_is_ip_blocked( $ip_to_check ) {
	global $wpdb; if ( empty( $ip_to_check ) ) return false;
	$table_name = $wpdb->prefix . 'ema_hardening_blocked_ips';
	$current_time = gmdate( 'Y-m-d H:i:s' );
	return ! is_null( $wpdb->get_var( $wpdb->prepare( "SELECT ip FROM $table_name WHERE ip = %s AND blocked_until > %s", $ip_to_check, $current_time ) ) );
}