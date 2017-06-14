<?php
if( is_admin() ) {
	new LogsentinelSettingsPage();
}

class LogsentinelSettingsPage {
	
	public function __construct() {
		add_action( 'admin_menu', array(&$this, 'create_menu'));
		add_action( 'admin_init', array(&$this, 'register_settings') );
	}
	
	public function create_menu() {
		// This page will be under "Settings"
        add_menu_page(
            'LogSentinel Setting', 
            'LogSentinel Setting', 
            'manage_options', 
            'logsentinel-setting-admin', 
            array( $this, 'create_admin_page' )
        );
	}

	public function register_settings() {
		register_setting( 'logsentinel-settings-group', 'url' );
		register_setting( 'logsentinel-settings-group', 'application_id' );
		register_setting( 'logsentinel-settings-group', 'organization_id' );
		register_setting( 'logsentinel-settings-group', 'secret' );
	}

	public function create_admin_page() {
	?>
	<div class="wrap">
	<h1>LogSentinel options</h1>

	<form method="post" action="options.php">
		<?php settings_fields( 'logsentinel-settings-group' ); ?>
		<?php do_settings_sections( 'logsentinel-settings-group' ); ?>
		<table class="form-table">
			<tr valign="top">
			<th scope="row" style="width: 250px;">LogSentinel root URL</th>
			<td><input type="text" name="url" value="<?php echo esc_attr( get_option('url', 'https://logsentinel.com') ); ?>" /></td>
			</tr>
			 
			<tr valign="top">
			<th scope="row" style="width: 250px;">Application ID</th>
			<td><input type="text" name="application_id" value="<?php echo esc_attr( get_option('application_id') ); ?>" /></td>
			</tr>
			
			<tr valign="top">
			<th scope="row" style="width: 250px;">Organization ID</th>
			<td><input type="text" name="organization_id" value="<?php echo esc_attr( get_option('organization_id') ); ?>" /></td>
			</tr>
			
			<tr valign="top">
			<th scope="row" style="width: 250px;">Secret</th>
			<td><input type="text" name="secret" value="<?php echo esc_attr( get_option('secret') ); ?>" /></td>
			</tr>
		</table>
		
		<?php submit_button(); ?>

	</form>
	</div>
<?php 
	}
}
?>