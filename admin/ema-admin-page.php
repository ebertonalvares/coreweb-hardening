<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'admin_menu', 'ema_hardening_add_admin_menu' );
function ema_hardening_add_admin_menu() {
	add_menu_page( 'EMA Hardening', 'EMA Security', 'manage_options', 'ema-hardening', 'ema_hardening_render_admin_page', 'dashicons-shield-alt', 90 );
}

function ema_hardening_render_admin_page() {
	global $wpdb;
	if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Você não tem permissão para acessar esta página.' ); }
	$table_name = $wpdb->prefix . 'ema_hardening_blocked_ips';
	if ( isset( $_POST['ema_action'] ) && $_POST['ema_action'] === 'clear_blocked_ips' ) {
		if ( isset( $_POST['_wpnonce_ema_clear_ips'] ) && wp_verify_nonce( sanitize_key( $_POST['_wpnonce_ema_clear_ips'] ), 'ema_clear_ips_action' ) ) {
			$wpdb->query( "TRUNCATE TABLE {$table_name}" );
			echo '<div class="notice notice-success is-dismissible"><p>Lista de IPs bloqueados foi limpa com sucesso!</p></div>';
		} else { echo '<div class="notice notice-error is-dismissible"><p>Falha na verificação de segurança.</p></div>'; }
	}
	$blocked_ips = $wpdb->get_results( "SELECT ip, blocked_until, reason FROM {$table_name} ORDER BY id DESC LIMIT 500", ARRAY_A );
	$is_file_edit_disabled = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
	$is_ssl_forced = defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN;
	$is_xmlrpc_disabled = ! apply_filters( 'xmlrpc_enabled', true );
	$is_wp_version_hidden = ! has_action( 'wp_head', 'wp_generator' );
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<p>Seu WordPress está sendo protegido pelo EMA Hardening Security.</p>
		<hr>
		<h2>Status da Proteção</h2>
		<table class="widefat fixed striped">
			<tbody>
				<tr><td>Firewall de Aplicação Web (WAF)</td><td><span style="color:green;">✅ Ativo</span></td></tr>
				<tr><td>Limite de Tentativas de Login</td><td><span style="color:green;">✅ Ativo</span></td></tr>
				<tr><td>Proteção de Usuários via API REST</td><td><span style="color:green;">✅ Ativo</span></td></tr>
				<tr><td>Honeypot Anti-Spam</td><td><span style="color:green;">✅ Ativo</span></td></tr>
				<tr><td>Cabeçalhos de Segurança HTTP</td><td><span style="color:green;">✅ Ativo</span></td></tr>
				<tr><td>XML-RPC Bloqueado</td><td><?php echo $is_xmlrpc_disabled ? '<span style="color:green;">✅ Ativo</span>' : '<span style="color:red;">❌ Inativo</span>'; ?></td></tr>
				<tr><td>Versão do WordPress Oculta</td><td><?php echo $is_wp_version_hidden ? '<span style="color:green;">✅ Ativo</span>' : '<span style="color:red;">❌ Inativo</span>'; ?></td></tr>
				<tr><td>Edição de Arquivos Desabilitada</td><td><?php echo $is_file_edit_disabled ? '<span style="color:green;">✅ Ativo (via wp-config.php)</span>' : '<span style="color:orange;">⚠️ Inativo. Adicione `define(\'DISALLOW_FILE_EDIT\', true);` ao wp-config.php para segurança máxima.</span>'; ?></td></tr>
				<tr><td>Forçar SSL no Admin</td><td><?php echo $is_ssl_forced ? '<span style="color:green;">✅ Ativo (via wp-config.php)</span>' : '<span style="color:orange;">⚠️ Inativo. Adicione `define(\'FORCE_SSL_ADMIN\', true);` ao wp-config.php para segurança máxima.</span>'; ?></td></tr>
			</tbody>
		</table>
		<hr>
		<h2>Log de IPs Bloqueados</h2>
		<?php if ( ! empty( $blocked_ips ) ) : ?>
			<table class="widefat fixed striped">
				<thead><tr><th>Endereço IP</th><th>Motivo</th><th>Bloqueado Até (UTC)</th></tr></thead>
				<tbody><?php foreach ( $blocked_ips as $entry ) : ?><tr><td><?php echo esc_html( $entry['ip'] ); ?></td><td><?php echo esc_html( $entry['reason'] ); ?></td><td><?php echo esc_html( $entry['blocked_until'] ); ?></td></tr><?php endforeach; ?></tbody>
			</table><br>
			<form method="post" action=""><input type="hidden" name="ema_action" value="clear_blocked_ips"><?php wp_nonce_field( 'ema_clear_ips_action', '_wpnonce_ema_clear_ips' ); ?><?php submit_button( 'Limpar Lista de IPs Bloqueados', 'delete small' ); ?></form>
		<?php else : ?><p>Nenhum IP bloqueado no momento.</p><?php endif; ?>
	</div>
	<?php
}