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
        
		$current_user = wp_get_current_user();
		$username = $current_user->user_login;
		
        $entity = $this->GetEntity($type);
        $action = $this->GetAction($type);
        $entityId = $this->GetEntityId($data, $entity);
        $root = get_option("url");
        $url = $root . '/api/log/' . $data['CurrentUserID'] . '/' . $action . '/' . $entity . '/' . $entityId . "?actorDisplayName=" . $username . "&userRoles=" . $this->GetRolesParam($data["CurrentUserRoles"]);
 
        $data["type"] = $type;
        $response = wp_remote_post( $url, array( 
            'body' => $data,
            'method' => "POST",
            'headers' => array("Authorization" => 'Basic ' . base64_encode(get_option("organization_id") . ':' . get_option("secret")), "Application-Id" => get_option("application_id"))
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
    
    private function GetRolesParam($roles) {
        $roleNames = array();
        foreach ($roles as $role) {
            array_push($roleNames, $role->name);
        }
        return implode(",", $roleNames);
    }
    
    private function EndsWith($string, $test) {
        $strlen = strlen($string);
        $testlen = strlen($test);
        if ($testlen > $strlen) return false;
        return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
    }
}
