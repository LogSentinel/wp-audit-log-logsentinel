<?php
class WSAL_Loggers_LogSentinelLogger extends WSAL_AbstractLogger
{
    public function __construct(WpSecurityAuditLog $plugin)
    {
        parent::__construct($plugin);
    }

    public function Log($type, $data = array(), $date = null, $siteid = null, $migrated = false)
    {
        // is this a php alert, and if so, are we logging such alerts?
        if ($type < 0010 && !$this->plugin->settings->IsPhpErrorLoggingEnabled()) return;
        if ($type == 9999) return; // skip promo events
		$organizationId = trim(get_option("organization_id"));
        if (!isset($organizationId) || $organizationId == "") return;
		
		$current_user = wp_get_current_user();
		$username = $current_user->user_login;
		
        $entity = $this->GetEntity($type);
        $action = $this->GetAction($type);
        $entityId = $this->GetEntityId($data, $entity);
        $root = get_option("url");
        $url = $root . '/api/log/' . $data['CurrentUserID'] . '/' . $action . '/' . $entity . '/' . $entityId . "?actorDisplayName=" . $username . "&actorRoles=" . implode(",", $data["CurrentUserRoles"]);
 
        $data["type"] = $type;
        $response = wp_remote_post( $url, array( 
            'body' => $this->json_encode($data),
            'method' => "POST",
            'headers' => array(
				"Authorization" => 'Basic ' . base64_encode(organizationId . ':' . trim(get_option("secret"))), 
				"Application-Id" => trim(get_option("application_id")),
				"Content-Type" => "application/json; charset=utf-8"
			)
        ) );
        $result = $response['body'];
        // do nothing with the result for now
    }
    
    private function GetEntity($type) {
        $alert = $this->plugin->alerts->GetAlerts()[$type];
        $entity = str_replace(" ", "_", str_replace("& ", "", $alert->subcatg));
        if ($this->EndsWith($entity, "s")) {
            $entity = substr($entity, 0, -1);
        }
        return $entity;
    }
    
    private function GetAction($type) {
        $alert = $this->plugin->alerts->GetAlerts()[$type];
        return str_replace(" ", "_", str_replace("& ", "", $alert->desc));
    }

    private function GetEntityId($data, $entity) {
        if (isset($data["PostID"])) {
            return $data["PostID"];
        } else if (isset($data["CommentID"])) {
            return $data["CommentID"];
        } else if (isset($data["TargetUserID"])) {
            return $data["TargetUserID"];
        } else if (isset($data["NewUserID"])) {
            return $data["NewUserID"];
        } else if (isset($data["MenuName"])) {
            return $data["MenuName"];
        } else if (isset($data["AttachmentID"])) {
            return $data["AttachmentID"];
        }
        return "NONE";
    }
    
    private function EndsWith($string, $test) {
        $strlen = strlen($string);
        $testlen = strlen($test);
        if ($testlen > $strlen) return false;
        return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
    }
	
	private function json_encode($data) {
		if (version_compare(PHP_VERSION, "5.4.0") >= 0) {
			return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
		} else {
			$flags = 128; // pretty-print
			$fails = implode('|', array_filter(array(
				'\\\\',
				$flags & JSON_HEX_TAG ? 'u003[CE]' : '',
				$flags & JSON_HEX_AMP ? 'u0026' : '',
				$flags & JSON_HEX_APOS ? 'u0027' : '',
				$flags & JSON_HEX_QUOT ? 'u0022' : '',
			)));
			$pattern = "/\\\\(?:(?:$fails)(*SKIP)(*FAIL)|u([0-9a-fA-F]{4}))/";
			$callback = function ($m) {
				return html_entity_decode("&#x$m[1];", ENT_QUOTES, 'UTF-8');
			};
			return preg_replace_callback($pattern, $callback, json_encode($input, $flags));
		}
	}
}
