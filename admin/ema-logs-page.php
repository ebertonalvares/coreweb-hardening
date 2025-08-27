<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'admin_menu', 'ema_hardening_logs_add_menu' );
function ema_hardening_logs_add_menu() {
	add_submenu_page( 'ema-hardening', 'Log de Atividades', 'Log de Atividades', 'manage_options', 'ema-activity-log', 'ema_hardening_logs_render_page' );
}

function ema_hardening_logs_render_page() {
	global $wpdb;
	$table_name = $wpdb->prefix . 'ema_hardening_logs';
	if ( isset( $_POST['ema_action'] ) && $_POST['ema_action'] === 'clear_logs' ) {
		if ( isset( $_POST['_wpnonce_ema_clear_logs'] ) && wp_verify_nonce( sanitize_key( $_POST['_wpnonce_ema_clear_logs'] ), 'ema_clear_logs_action' ) ) {
			$wpdb->query( "TRUNCATE TABLE {$table_name}" );
			echo '<div class="notice notice-success is-dismissible"><p>Log de atividades limpo com sucesso!</p></div>';
		}
	}
	$per_page = 30; $current_page = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1; $offset = ( $current_page - 1 ) * $per_page;
	$total_items = $wpdb->get_var( "SELECT COUNT(id) FROM {$table_name}" ); $total_pages = ceil( $total_items / $per_page );
	$logs = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table_name} ORDER BY event_time DESC LIMIT %d OFFSET %d", $per_page, $offset ), ARRAY_A );
	?>
	<div class="wrap">
		<h1>Log de Atividades</h1>
		<p>Este log registra eventos importantes que acontecem no seu site.</p>
		<form method="post" action="">
			<input type="hidden" name="ema_action" value="clear_logs">
			<?php wp_nonce_field( 'ema_clear_logs_action', '_wpnonce_ema_clear_logs' ); ?>
			<?php submit_button( 'Limpar Log Completo', 'delete small', 'submit', false, [ 'onclick' => "return confirm('Você tem certeza que deseja deletar todo o log de atividades? Esta ação não pode ser desfeita.');" ] ); ?>
		</form>
		<table class="widefat fixed striped">
			<thead><tr><th style="width:15%;">Data (UTC)</th><th style="width:10%;">Usuário</th><th style="width:10%;">Endereço IP</th><th style="width:15%;">Tipo de Evento</th><th>Detalhes</th></tr></thead>
			<tbody>
				<?php if ( ! empty( $logs ) ) : foreach ( $logs as $log ) : ?>
					<tr><td><?php echo esc_html( $log['event_time'] ); ?></td><td><?php if ( $log['user_id'] > 0 ) { $user = get_userdata( $log['user_id'] ); echo $user ? esc_html( $user->user_login ) : 'ID: ' . esc_html( $log['user_id'] ); } else { echo 'Sistema/Visitante'; } ?></td><td><?php echo esc_html( $log['ip_address'] ); ?></td><td><?php echo esc_html( str_replace( '_', ' ', ucfirst( $log['event_type'] ) ) ); ?></td><td><?php echo esc_html( $log['details'] ); ?></td></tr>
				<?php endforeach; else : ?><tr><td colspan="5">Nenhum registro encontrado.</td></tr><?php endif; ?>
			</tbody>
		</table>
		<div class="tablenav"><div class="tablenav-pages"><span class="displaying-num"><?php echo esc_html( $total_items ); ?> itens</span><span class="pagination-links"><?php echo paginate_links( [ 'base' => add_query_arg( 'paged', '%#%' ), 'format' => '', 'prev_text' => '&laquo;', 'next_text' => '&raquo;', 'total' => $total_pages, 'current' => $current_page ] ); ?></span></div></div>
	</div>
	<?php
}