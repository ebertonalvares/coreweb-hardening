<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'admin_menu', 'ema_hardening_scanner_add_menu' );
function ema_hardening_scanner_add_menu() {
	add_submenu_page( 'ema-hardening', 'Scanner de Segurança', 'Scanner de Segurança', 'manage_options', 'ema-security-scanner', 'ema_hardening_scanner_render_page' );
}

add_action( 'admin_enqueue_scripts', 'ema_hardening_scanner_enqueue_scripts' );
function ema_hardening_scanner_enqueue_scripts( $hook ) {
	if ( 'ema-security_page_ema-security-scanner' !== $hook ) { return; }
	wp_enqueue_script( 'ema-scanner-js', plugin_dir_url( __FILE__ ) . 'js/scanner.js', [ 'jquery' ], EMA_HARDENING_VERSION, true );
	wp_localize_script( 'ema-scanner-js', 'ema_scanner_ajax', [
		'ajax_url' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'ema_scanner_nonce' ),
		'strings'  => [
			'preparing' => 'Preparando verificação...', 'executing_step' => 'Executando etapa:', 'scan_complete' => 'Verificação Concluída!', 'results_title' => 'Resultados da Verificação', 'error_generic' => 'Ocorreu um erro inesperado.', 'error_details' => 'Por favor, verifique o console do desenvolvedor do seu navegador (F12) para mais detalhes.', 'core_title' => 'Verificação de Integridade do Core', 'modified_title' => 'Arquivos do Core Modificados:', 'unknown_title' => 'Arquivos Desconhecidos nos Diretórios do Core:', 'malware_title' => 'Assinaturas de Malware Encontradas', 'database_title' => 'Análise do Banco de Dados', 'reason' => 'Motivo', 'restore_btn' => 'Restaurar', 'delete_btn' => 'Deletar', 'confirm_delete' => 'Você tem certeza que deseja deletar este arquivo? Esta ação não pode ser desfeita.',
		],
	] );
}

function ema_hardening_scanner_render_page() {
	?>
	<style>
		#scan-live-log { background-color: #23282d; color: #a4afb7; padding: 15px; font-family: monospace; max-height: 250px; overflow-y: auto; border-radius: 4px; margin-top: 15px; white-space: pre-wrap; display:none; }
	</style>
	<div class="wrap">
		<h1>Scanner de Segurança</h1>
		<p>Esta ferramenta verifica sua instalação do WordPress em busca de modificações, arquivos suspeitos e possíveis problemas no banco de dados.</p>
		<p><strong>Importante:</strong> Antes de restaurar ou deletar qualquer arquivo, por favor, garanta que você tem um backup completo do seu site.</p>
		<div id="scanner-controls"><button id="start-scan-btn" class="button button-primary">Iniciar Verificação Completa</button></div>
		<div id="scan-results-container" style="margin-top: 20px;">
			<div id="scan-status"></div>
			<pre id="scan-live-log"></pre>
			<div id="scan-results"></div>
		</div>
	</div>
	<?php
}

add_action( 'wp_ajax_ema_scanner_controller', 'ema_hardening_scanner_controller_ajax' );
function ema_hardening_scanner_controller_ajax() {
	check_ajax_referer( 'ema_scanner_nonce', 'nonce' );
	if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( [ 'message' => 'Permission Denied.' ] ); }
	$step = isset( $_POST['step'] ) ? sanitize_key( $_POST['step'] ) : 'start';
	switch ( $step ) {
		case 'start':
			delete_transient( 'ema_scan_file_list' ); delete_transient( 'ema_scan_dir_queue' );
			set_transient( 'ema_scan_dir_queue', [ ABSPATH ], HOUR_IN_SECONDS );
			set_transient( 'ema_scan_file_list', [], HOUR_IN_SECONDS );
			wp_send_json_success( [ 'next_step' => 'build_file_list', 'status' => 'Iniciando a construção da lista de arquivos...', 'log_message' => 'Fila de diretórios iniciada.' ] );
			break;
		case 'build_file_list':
			$dir_queue = get_transient( 'ema_scan_dir_queue' );
			if ( empty( $dir_queue ) ) { wp_send_json_success( [ 'next_step' => 'core_integrity', 'status' => 'Lista de arquivos construída. Iniciando verificação do Core...', 'log_message' => 'Construção da lista de arquivos finalizada.' ] ); return; }
			$current_dir = array_shift( $dir_queue ); $file_list = get_transient( 'ema_scan_file_list' );
			$exclude = [ '.git', 'node_modules', 'cache' ];
			try {
				if ( ! is_readable( $current_dir ) ) { throw new Exception(); }
				$iterator = new DirectoryIterator( $current_dir );
				foreach ( $iterator as $fileinfo ) {
					if ( $fileinfo->isDot() ) continue;
					$path = $fileinfo->getPathname();
					if ( $fileinfo->isDir() ) { foreach ( $exclude as $ex_dir ) { if ( strpos( $path, DIRECTORY_SEPARATOR . $ex_dir ) !== false ) { continue 2; } } $dir_queue[] = $path;
					} elseif ( $fileinfo->isFile() ) { $file_list[] = $path; }
				}
			} catch ( Exception $e ) { /* Ignora diretórios/arquivos ilegíveis */ }
			set_transient( 'ema_scan_dir_queue', $dir_queue, HOUR_IN_SECONDS ); set_transient( 'ema_scan_file_list', $file_list, HOUR_IN_SECONDS );
			$log_message = 'Processando: ' . str_replace( ABSPATH, '', $current_dir );
			wp_send_json_success( [ 'next_step' => 'build_file_list', 'status' => sprintf( 'Construindo lista de arquivos... (%d diretórios na fila)', count( $dir_queue ) ), 'log_message' => $log_message ] );
			break;
		case 'core_integrity':
			wp_send_json_success( [ 'results' => ema_hardening_scan_core_files(), 'next_step' => 'content_scan', 'status' => 'Verificação do Core finalizada. Iniciando verificação de conteúdo...', 'log_message' => 'Analisando arquivos do Core do WordPress.' ] );
			break;
		case 'content_scan':
			$files = get_transient( 'ema_scan_file_list' ); $batch_size = 200;
			if ( empty( $files ) ) { wp_send_json_success( [ 'results' => [], 'next_step' => 'database_scan', 'status' => 'Verificação de conteúdo finalizada. Iniciando verificação do banco de dados...', 'log_message' => 'Análise de arquivos finalizada.' ] ); return; }
			$current_batch = array_slice( $files, 0, $batch_size ); $remaining_files = array_slice( $files, $batch_size );
			set_transient( 'ema_scan_file_list', $remaining_files, HOUR_IN_SECONDS );
			$log_message = 'Verificando lote de ' . count($current_batch) . ' arquivos, iniciando com: ' . str_replace( ABSPATH, '', $current_batch[0] );
			wp_send_json_success( [ 'results' => ema_hardening_scan_file_signatures( $current_batch ), 'next_step' => 'content_scan', 'status' => sprintf( 'Verificando arquivos de conteúdo... (%d restantes)', count( $remaining_files ) ), 'log_message' => $log_message ] );
			break;
		case 'database_scan':
			delete_transient( 'ema_scan_file_list' ); delete_transient( 'ema_scan_dir_queue' );
			wp_send_json_success( [ 'results' => ema_hardening_scan_database(), 'next_step' => 'finished', 'status' => 'Verificação completa!', 'log_message' => 'Analisando o banco de dados.' ] );
			break;
	}
}

add_action( 'wp_ajax_ema_repair_core_file', 'ema_hardening_handle_repair_file_ajax' );
function ema_hardening_handle_repair_file_ajax() { check_ajax_referer( 'ema_scanner_nonce', 'nonce' ); if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( [ 'message' => 'Permission denied.' ] ); } $file_to_repair = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : ''; if ( empty( $file_to_repair ) ) { wp_send_json_error( [ 'message' => 'Invalid file specified.' ] ); } require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); global $wp_filesystem; $destination_file = $wp_filesystem->abspath() . $file_to_repair; $source_path = ema_hardening_get_core_source(); if ( is_wp_error( $source_path ) ) { wp_send_json_error( [ 'message' => $source_path->get_error_message() ] ); } $source_file = trailingslashit( $source_path ) . $file_to_repair; if ( ! $wp_filesystem->exists( $source_file ) ) { wp_send_json_error( [ 'message' => 'Original file not found in WordPress source.' ] ); } if ( $wp_filesystem->copy( $source_file, $destination_file, true ) ) { wp_send_json_success( [ 'message' => 'Arquivo restaurado com sucesso.' ] ); } else { wp_send_json_error( [ 'message' => 'Could not restore file. Check file permissions.' ] ); } }
add_action( 'wp_ajax_ema_delete_unknown_file', 'ema_hardening_handle_delete_file_ajax' );
function ema_hardening_handle_delete_file_ajax() { check_ajax_referer( 'ema_scanner_nonce', 'nonce' ); if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( [ 'message' => 'Permission denied.' ] ); } $file_to_delete = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : ''; if ( empty( $file_to_delete ) || strpos( $file_to_delete, '..' ) !== false ) { wp_send_json_error( [ 'message' => 'Invalid file specified.' ] ); } require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); global $wp_filesystem; $full_path = $wp_filesystem->abspath() . $file_to_delete; if ( ! $wp_filesystem->exists( $full_path ) ) { wp_send_json_error( [ 'message' => 'File does not exist.' ] ); } if ( $wp_filesystem->delete( $full_path ) ) { wp_send_json_success( [ 'message' => 'Arquivo deletado com sucesso.' ] ); } else { wp_send_json_error( [ 'message' => 'Could not delete file. Check file permissions.' ] ); } }
function ema_hardening_get_core_source() { global $wp_version, $wp_filesystem; $locale = get_locale(); $upload_dir = wp_upload_dir(); $temp_dir = trailingslashit( $upload_dir['basedir'] ) . 'ema-temp-core'; $wp_source_dir = trailingslashit( $temp_dir ) . 'wordpress'; if ( ! isset( $wp_filesystem ) || is_null( $wp_filesystem ) ) { WP_Filesystem(); } if ( $wp_filesystem->exists( $wp_source_dir ) ) { return $wp_source_dir; } if ( ! wp_mkdir_p( $temp_dir ) ) { return new WP_Error( 'dir_creation_failed', 'Could not create temporary directory.' ); } $download_url = "https://wordpress.org/wordpress-{$wp_version}.zip"; if ( 'en_US' !== $locale ) { $download_url = "https://downloads.wordpress.org/release/{$locale}/wordpress-{$wp_version}.zip"; } $temp_file = download_url( $download_url, 300 ); if ( is_wp_error( $temp_file ) ) { return $temp_file; } $unzip_result = unzip_file( $temp_file, $temp_dir ); $wp_filesystem->delete( $temp_file ); if ( is_wp_error( $unzip_result ) ) { return $unzip_result; } return $wp_source_dir; }
function ema_hardening_scan_core_files() { global $wp_version; $locale = get_locale(); $api_url = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}"; $response = wp_remote_get( $api_url ); if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) { return [ 'type' => 'core_integrity', 'error' => 'Could not fetch checksums from WordPress.org API.' ]; } $body = wp_remote_retrieve_body( $response ); $data = json_decode( $body, true ); $checksums = isset( $data['checksums'] ) ? $data['checksums'] : null; if ( ! $checksums ) { return [ 'type' => 'core_integrity', 'error' => 'Invalid checksum data received from API.' ]; } $results = [ 'modified' => [], 'unknown' => [] ]; $core_dirs = [ 'wp-admin', 'wp-includes' ]; foreach ( $core_dirs as $dir ) { try { $iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( ABSPATH . $dir, RecursiveDirectoryIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD ); foreach ( $iterator as $file ) { if ( $file->isFile() ) { $relative_path = str_replace( ABSPATH, '', $file->getPathname() ); $relative_path = str_replace( '\\', '/', $relative_path ); if ( isset( $checksums[ $relative_path ] ) ) { if ( @md5_file( $file->getPathname() ) !== $checksums[ $relative_path ] ) { $results['modified'][] = $relative_path; } } else { $results['unknown'][] = $relative_path; } } } } catch ( Exception $e ) { continue; } } return [ 'type' => 'core_integrity', 'issues' => $results ]; }
function ema_hardening_scan_file_signatures($files) { $results = [ 'type' => 'malware_signature', 'issues' => [] ]; $malware_signatures = [ '/\b(eval|exec|system|passthru|shell_exec)\s*\(\s*base64_decode\s*\(/i' => 'Código Malicioso Potencialmente Ofuscado', '/p-h-p-s-h-e-l-l|c99shell|r57shell|prida|pridaxpl/i' => 'Nome de Webshell Conhecido', '/\<\?php \/\*NUKE\*\//i' => 'Assinatura de Malware Conhecida (NUKE)', '/FilesMan/i' => 'Nome de Webshell Conhecido (FilesMan)', ]; $upload_dir = wp_upload_dir(); $upload_path = $upload_dir['basedir']; foreach ( $files as $file_path ) { if ( strpos( $file_path, $upload_path ) === 0 && preg_match( '/\.(php|phtml|php[3-7]|phar)$/i', $file_path ) ) { $results['issues'][] = [ 'file' => str_replace( ABSPATH, '', $file_path ), 'reason' => 'Arquivo PHP encontrado no diretório de uploads', 'type' => 'suspicious_file' ]; } $content = @file_get_contents( $file_path ); if ( empty( $content ) ) continue; foreach ( $malware_signatures as $regex => $reason ) { if ( preg_match( $regex, $content ) ) { $results['issues'][] = [ 'file' => str_replace( ABSPATH, '', $file_path ), 'reason' => $reason, 'type' => 'malware_pattern' ]; } } } return $results; }
function ema_hardening_scan_database() { global $wpdb; $results = [ 'type' => 'database_scan', 'issues' => [] ]; $suspicious_posts = $wpdb->get_results( "SELECT ID, post_title, post_type FROM {$wpdb->posts} WHERE post_status = 'publish' AND (post_content LIKE '%<script%' OR post_content LIKE '%<iframe%')" ); if ( $suspicious_posts ) { foreach ( $suspicious_posts as $post ) { $results['issues'][] = [ 'reason' => 'Conteúdo suspeito (script/iframe) encontrado em', 'details' => sprintf( '%s: <a href="%s" target="_blank">%s</a>', ucfirst($post->post_type), get_edit_post_link($post->ID), esc_html($post->post_title) ), 'type' => 'suspicious_content' ]; } } $siteurl = get_option( 'siteurl' ); $home = get_option( 'home' ); $db_siteurl = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'siteurl'" ); $db_home = $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name = 'home'" ); if ( $siteurl !== $db_siteurl || $home !== $db_home ) { $results['issues'][] = [ 'reason' => 'Divergência de URL do site no banco de dados', 'details' => sprintf( 'Esperado: %s / Encontrado: %s.', $siteurl, $db_siteurl ), 'type' => 'url_mismatch' ]; } $admin_users = get_users( [ 'role' => 'administrator' ] ); if ( $admin_users ) { $user_list = []; foreach ( $admin_users as $user ) { $user_list[] = esc_html( $user->user_login ); } $results['issues'][] = [ 'reason' => 'Usuários administradores para revisão', 'details' => implode( ', ', $user_list ), 'type' => 'admin_review' ]; } return $results; }