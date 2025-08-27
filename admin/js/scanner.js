jQuery(document).ready(function ($) {
    var $button = $('#start-scan-btn');
    var $status = $('#scan-status');
    var $log = $('#scan-live-log');
    var $resultsDiv = $('#scan-results');
    var s = ema_scanner_ajax.strings;

    $button.on('click', function () {
        $button.prop('disabled', true);
        $resultsDiv.empty().html('<h3>' + s.results_title + '</h3>');
        $log.empty().show();
        runScanStep('start');
    });

    function runScanStep(step) {
        var statusText = step === 'start' ? s.preparing : s.executing_step + ' ' + step.replace(/_/g, ' ');
        $status.html('<p><em><span class="spinner is-active" style="float:left; margin-right:5px;"></span>' + statusText + '</em></p>');
        $.ajax({
            url: ema_scanner_ajax.ajax_url, type: 'POST',
            data: { action: 'ema_scanner_controller', nonce: ema_scanner_ajax.nonce, step: step },
            success: function (response) {
                if (response.success) {
                    if (response.data.status) { $status.html('<p><em><span class="spinner is-active" style="float:left; margin-right:5px;"></span>' + response.data.status + '</em></p>'); }
                    if (response.data.log_message) {
                        $log.append(document.createTextNode(response.data.log_message + '\n'));
                        $log.scrollTop($log[0].scrollHeight);
                    }
                    if (response.data.results) { renderResults(response.data.results); }
                    if (response.data.next_step && response.data.next_step !== 'finished') {
                        runScanStep(response.data.next_step);
                    } else {
                        $status.html('<p><strong>' + s.scan_complete + '</strong></p>');
                        $log.append(document.createTextNode('\n' + s.scan_complete + '\n'));
                        $log.scrollTop($log[0].scrollHeight);
                        $button.prop('disabled', false);
                    }
                } else {
                    $status.html('<p style="color:red;"><strong>Erro:</strong> ' + response.data.message + '</p>');
                    $button.prop('disabled', false);
                }
            },
            error: function (jqXHR) {
                console.error("AJAX Error Details:", { status: jqXHR.status, statusText: jqXHR.statusText, responseText: jqXHR.responseText });
                $status.html('<p style="color:red;"><strong>' + s.error_generic + '</strong><br><small>Status: ' + jqXHR.status + '. ' + s.error_details + '</small></p>');
                $button.prop('disabled', false);
            }
        });
    }

    function renderResults(data) {
        if (data.error || (!data.issues || (Array.isArray(data.issues) && data.issues.length === 0) || (typeof data.issues === 'object' && Object.keys(data.issues).length === 0 && !data.issues.modified && !data.issues.unknown)) ) { return; }
        var output = '';
        if (data.type === 'core_integrity') {
            output += '<h4>' + s.core_title + '</h4>';
            if(data.issues.modified && data.issues.modified.length > 0) {
                output += '<p><strong>' + s.modified_title + '</strong></p><ul>';
                data.issues.modified.forEach(function(file) { output += '<li><code>' + file + '</code> <button class="button button-secondary ema-repair-btn" data-file="' + file + '">' + s.restore_btn + '</button> <span class="spinner"></span></li>'; });
                output += '</ul>';
            }
            if(data.issues.unknown && data.issues.unknown.length > 0) {
                output += '<p><strong>' + s.unknown_title + '</strong></p><ul>';
                data.issues.unknown.forEach(function(file) { output += '<li><code>' + file + '</code> <button class="button button-secondary ema-delete-btn" data-file="' + file + '">' + s.delete_btn + '</button> <span class="spinner"></span></li>'; });
                output += '</ul>';
            }
        } else if (data.type === 'malware_signature') {
            output += '<h4>' + s.malware_title + '</h4><ul>';
            data.issues.forEach(function (issue) { output += '<li><code>' + issue.file + '</code> - <strong>' + s.reason + ':</strong> ' + issue.reason + '</li>'; });
            output += '</ul>';
        } else if (data.type === 'database_scan') {
            output += '<h4>' + s.database_title + '</h4><ul>';
            data.issues.forEach(function (issue) { output += '<li><strong>' + issue.reason + ':</strong> ' + issue.details + '</li>'; });
            output += '</ul>';
        }
        if (output) { $resultsDiv.append(output); }
    }
    
    $resultsDiv.on('click', '.ema-repair-btn', function (e) { e.preventDefault(); var $button = $(this); var file = $button.data('file'); $button.prop('disabled', true).siblings('.spinner').addClass('is-active'); $.ajax({ url: ema_scanner_ajax.ajax_url, type: 'POST', data: { action: 'ema_repair_core_file', nonce: ema_scanner_ajax.nonce, file: file }, success: function(response) { $button.siblings('.spinner').removeClass('is-active'); if (response.success) { $button.replaceWith('<span style="color:green;">✔ ' + response.data.message + '</span>'); } else { $button.prop('disabled', false).after('<span style="color:red; margin-left:10px;">' + response.data.message + '</span>'); } }, error: function(jqXHR) { console.error(jqXHR.responseText); $button.prop('disabled', false).siblings('.spinner').removeClass('is-active'); $button.after('<span style="color:red; margin-left:10px;">' + s.error_generic + '</span>'); } }); });
    $resultsDiv.on('click', '.ema-delete-btn', function (e) { e.preventDefault(); if (!confirm(s.confirm_delete)) { return; } var $button = $(this); var file = $button.data('file'); $button.prop('disabled', true).siblings('.spinner').addClass('is-active'); $.ajax({ url: ema_scanner_ajax.ajax_url, type: 'POST', data: { action: 'ema_delete_unknown_file', nonce: ema_scanner_ajax.nonce, file: file }, success: function(response) { $button.siblings('.spinner').removeClass('is-active'); if (response.success) { $button.replaceWith('<span style="color:green;">✔ ' + response.data.message + '</span>'); } else { $button.prop('disabled', false).after('<span style="color:red; margin-left:10px;">' + response.data.message + '</span>'); } }, error: function(jqXHR) { console.error(jqXHR.responseText); $button.prop('disabled', false).siblings('.spinner').removeClass('is-active'); $button.after('<span style="color:red; margin-left:10px;">' + s.error_generic + '</span>'); } }); });
});