<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

function ema_hardening_log_event( $type, $details, $user_id = null ) {
	global $wpdb; $user_id = is_null( $user_id ) ? get_current_user_id() : $user_id;
	$wpdb->insert( $wpdb->prefix . 'ema_hardening_logs', [ 'user_id' => $user_id, 'ip_address' => ema_hardening_get_user_ip(), 'event_type' => $type, 'details' => $details, 'event_time' => current_time( 'mysql', true ) ], [ '%d', '%s', '%s', '%s', '%s' ] );
}

add_action( 'wp_login', function( $user_login, $user ) { ema_hardening_log_event( 'login_success', sprintf( 'Usuário "%s" logado com sucesso.', $user->user_login ), $user->ID ); }, 10, 2 );

add_action( 'wp_login_failed', 'ema_hardening_log_failed_login', 10, 2 );
function ema_hardening_log_failed_login( $username, $error ) {
	$ip = ema_hardening_get_user_ip();
	ema_hardening_log_event( 'login_failed', sprintf( 'Tentativa de login falhou para o usuário: "%s".', $username ), 0 );
	$transient_key = 'ema_login_failed_' . $ip;
	$attempts = (int) get_transient( $transient_key ) + 1;
	set_transient( $transient_key, $attempts, EMA_LOGIN_LOCKOUT_DURATION );
	if ( $attempts >= EMA_LOGIN_ATTEMPTS_LIMIT ) { ema_hardening_block_ip( $ip, 'Brute-force: Login Lockout', EMA_LOGIN_LOCKOUT_DURATION ); }
}

add_action( 'activated_plugin', function( $plugin ) { ema_hardening_log_event( 'plugin_activated', sprintf( 'Plugin ativado: %s', $plugin ) ); }, 10, 1 );
add_action( 'deactivated_plugin', function( $plugin ) { ema_hardening_log_event( 'plugin_deactivated', sprintf( 'Plugin desativado: %s', $plugin ) ); }, 10, 1 );
add_action( 'switch_theme', function( $new_theme_name ) { ema_hardening_log_event( 'theme_switched', sprintf( 'Tema alterado para: %s', $new_theme_name ) ); }, 10, 1 );
add_action( 'save_post', function( $post_id, $post, $update ) { if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE || wp_is_post_revision( $post_id ) ) return; ema_hardening_log_event( 'post_' . ( $update ? 'updated' : 'created' ), sprintf( 'Post "%s" (ID: %d, Tipo: %s) foi %s.', $post->post_title, $post_id, $post->post_type, ( $update ? 'atualizado' : 'criado' ) ) ); }, 10, 3 );
add_action( 'delete_post', function( $post_id ) { $post = get_post( $post_id ); if(!$post) return; ema_hardening_log_event( 'post_deleted', sprintf( 'Post "%s" (ID: %d, Tipo: %s) foi deletado.', $post->post_title, $post_id, $post->post_type ) ); }, 10, 1 );
add_action( 'user_register', function( $user_id ) { $user = get_userdata( $user_id ); ema_hardening_log_event( 'user_created', sprintf( 'Novo usuário criado: "%s" (ID: %d).', $user->user_login, $user_id ) ); }, 10, 1 );
add_action( 'delete_user', function( $user_id ) { $user = get_userdata( $user_id ); if(!$user) return; ema_hardening_log_event( 'user_deleted', sprintf( 'Usuário deletado: "%s" (ID: %d).', $user->user_login, $user_id ) ); }, 10, 1 );