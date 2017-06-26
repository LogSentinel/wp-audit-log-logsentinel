<?php
/*
  Plugin Name: LogSentinel storage for WP Security Audit Log
  Plugin URI: https://github.com/logsentimel/wp-audit-log-logsentinel
  Description: An addon to WP Security Audit Log Plugin to store events in LogSentinel.com
  Version: 0.3
  Author: Bozhdiar Bozhanov
  Author URI:
  Depends: WP Security Audit Log
  License: GPL3
  */

// don't call this class directly
if ( ! class_exists( 'WP' ) ) {
	die();
}
include_once(plugin_dir_path( __FILE__ ) . "includes/options.php");

defined( 'ABSPATH' ) or die( 'Can\'t be invoked directly' );

register_activation_hook( __FILE__, 'logsentinel_plugin_activation' );

function logsentinel_plugin_activation() {
	global $wp_version;
	$min_wsal_version  = '2.6.2';
	$wsal_plugin_dir   = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . 'wp-security-audit-log/wp-security-audit-log.php';
	
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}

	$wsalData = get_plugin_data( $wsal_plugin_dir, false, true );
	if ( isset( $wsalData['Version'] ) && ( version_compare( $wsalData['Version'], $min_wsal_version, '<' ) ) ) {
		deactivate_plugins( basename( __FILE__ ) );
		wp_die(
			'<p>' .
			sprintf(
				'This plugin can not be activated because it requires at least version %s of WP Security Audit Log. Please upgrade WP Security Audit Log and then re-activate this plugin.',
				$min_wsal_version
			)
			. '</p> <a href="' . admin_url( 'plugins.php' ) . '">' . 'go back' . '</a>'
		);
	}
}

function logsentimel_wsal_init ($wsal) {

    $rootDir = trailingslashit( dirname( __FILE__ ) );
    $loggersDirPath =  $rootDir . 'Loggers' . DIRECTORY_SEPARATOR ;

    if (is_dir($loggersDirPath) && is_readable($loggersDirPath)) {
        foreach (glob($loggersDirPath . '*.php') as $file) {
	        require_once($file);
            $file = substr($file, 0, -4);
            $class = "WSAL_Loggers_" . str_replace($loggersDirPath, '', $file);
	        $wsal->alerts->AddFromClass($class);
        }
    }
}
add_action('wsal_init', 'logsentimel_wsal_init');

