<?php
class ServiceProvider_Aws extends Extension_ServiceProvider implements IServiceProvider_HttpRequestSigner {
	const ID = 'wgm.aws.service.provider';
	
	function renderConfigForm(Model_ConnectedAccount $account) {
		$tpl = DevblocksPlatform::getTemplateService();
		$active_worker = CerberusApplication::getActiveWorker();
		
		$params = $account->decryptParams($active_worker);
		$tpl->assign('params', $params);
		
		$tpl->display('devblocks:wgm.aws::providers/edit_params.tpl');
	}
	
	function saveConfigForm(Model_ConnectedAccount $account, array &$params) {
		@$edit_params = DevblocksPlatform::importGPC($_POST['params'], 'array', array());
		
		$active_worker = CerberusApplication::getActiveWorker();
		$encrypt = DevblocksPlatform::getEncryptionService();
		
		if(!isset($edit_params['access_key']) || empty($edit_params['access_key']))
			return "The 'Access Key ID' is required.";
		
		if(!isset($edit_params['secret_key']) || empty($edit_params['secret_key']))
			return "The 'Secret Access Key' is required.";
		
		$account->id = 0;
		$account->params_json_encrypted = $encrypt->encrypt(json_encode($edit_params));
		
		$verb = 'GET';
		$url = 'https://iam.amazonaws.com/?Action=GetUser&Version=2010-05-08';
		$body = '';
		$headers = [];
		$ch = DevblocksPlatform::curlInit($url);
		$return = $account->authenticateHttpRequest($ch, $verb, $url, $body, $headers, $active_worker);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $verb);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		$xml = DevblocksPlatform::curlExec($ch, false, true);
		
		$info = curl_getinfo($ch);
		
		if($info['http_code'] != 200) {
			return 'Failed to test iam::GetUser';
		}
		
		$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA);
		$json = json_encode($doc);
		
		@$user_id = $json['GetUserResult']['User']['UserId'];
		
		if(!$user_id)
			return 'Failed to test iam::GetUser';
		
		foreach($edit_params as $k => $v)
			$params[$k] = $v;
			
		return true;
	}
	
	private function _createCanonicalPath($url_parts) {
		$path = @$url_parts['path'] ?: '/';
		$path_parts = explode('/', $path);
		
		foreach($path_parts as &$segment)
			$segment = rawurlencode($segment);
		
		return implode('/', $path_parts);
	}
	
	private function _createCanonicalQueryString($url_parts) {
		$query = @$url_parts['query'] ?: '';
		$query_parts = [];
		$canonical_query = '';
		$query_parts = DevblocksPlatform::strParseQueryString($query);
		
		ksort($query_parts, SORT_STRING);
		
		foreach($query_parts as $key => $part)
			$canonical_query .= $key . '=' . rawurlencode($part) . '&';
		
		$canonical_query = rtrim($canonical_query, '&');
		
		return $canonical_query;
	}
	
	private function _createCanonicalHeaders($headers) {
		$canonical_headers = '';
		
		sort($headers, SORT_STRING | SORT_FLAG_CASE);
		
		foreach($headers as $header) {
			@list($key, $val) = explode(':', $header, 2);
			$canonical_headers .= DevblocksPlatform::strLower(trim($key)) . ':' . trim($val) . "\n";
		}
		
		return $canonical_headers;
	}
	
	private function _createSignedHeaders($headers) {
		$signed_headers = [];
		
		foreach($headers as $header) {
			@list($key, $val) = explode(':', $header, 2);
			$signed_headers[] = DevblocksPlatform::strLower(trim($key));
		}
		
		sort($signed_headers, SORT_STRING | SORT_FLAG_CASE);
		
		return implode(';', $signed_headers);
	}
	
	function authenticateHttpRequest(Model_ConnectedAccount $account, &$ch, &$verb, &$url, &$body, &$headers) {
		$credentials = $account->decryptParams();
		
		if(
			!isset($credentials['access_key'])
			|| !isset($credentials['secret_key'])
			|| !is_array($headers)
		)
			return false;
		
		if(false == ($url_parts = parse_url($url)))
			return false;
		
		$date_iso_8601 = gmdate('Ymd\THis\Z');
			
		$header_keys = [];
		foreach($headers as $header) {
			list($key, $val) = explode(':', $header, 2);
			$header_keys[DevblocksPlatform::strLower(trim($key))] = true;
		}
		
		if(!isset($header_keys['x-amz-date']))
			$headers[] = 'X-AMZ-Date: ' . $date_iso_8601;
		
		if(!isset($header_keys['host']))
			$headers[] = 'Host: ' . $url_parts['host'];
		
		// Derive service + region from URL
		$matches = [];
		$service = $region = null;
		
		if(preg_match('#^(.*?)\.(.*?)\.amazonaws\.com$#', $url_parts['host'], $matches)) {
			$service = DevblocksPlatform::strLower($matches[1]);
			$region = DevblocksPlatform::strLower($matches[2]);
			
		} else if(preg_match('#^(.*?)\.amazonaws\.com$#', $url_parts['host'], $matches)) {
			$service = $matches[1];
			$region = 'us-east-1';
		}
		
		if(empty($region) || empty($service))
			return false;
		
		$canonical_path = $this->_createCanonicalPath($url_parts);
		$canonical_query = $this->_createCanonicalQueryString($url_parts);
		$canonical_headers = $this->_createCanonicalHeaders($headers);
		$signed_headers = $this->_createSignedHeaders($headers);
		
		$canonical_string = 
			DevblocksPlatform::strUpper($verb) . "\n" .
			$canonical_path . "\n" .
			$canonical_query . "\n" .
			$canonical_headers . "\n" .
			$signed_headers . "\n" .
			DevblocksPlatform::strLower(hash('sha256', $body))
			;
		
		$credential_scope = sprintf("%s/%s/%s/aws4_request",
			gmdate("Ymd"),
			$region,
			$service
		);
		
		$string_to_sign = 
			'AWS4-HMAC-SHA256' . "\n" .
			$date_iso_8601 . "\n" .
			$credential_scope . "\n" .
			DevblocksPlatform::strLower(hash('sha256', $canonical_string))
			;
		
		$secret = $credentials['secret_key'];
		$hash_date = hash_hmac('sha256', gmdate('Ymd'), 'AWS4' . $secret, true);
		$hash_region = hash_hmac('sha256', $region, $hash_date, true);
		$hash_service = hash_hmac('sha256', $service, $hash_region, true);
		$hash_signing = hash_hmac('sha256', 'aws4_request', $hash_service, true);
		
		$signature = hash_hmac('sha256', $string_to_sign, $hash_signing, false);
		
		$headers[] = sprintf('Authorization: %s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
			'AWS4-HMAC-SHA256',
			$credentials['access_key'],
			$credential_scope,
			$signed_headers,
			$signature
		);
		
		return true;
	}
	
	// [TODO] Check privs
	function generatePresignedUrl(Model_ConnectedAccount $account, $ch, $verb, $url, $body, $headers, $expires_secs=300) {
		$credentials = $account->decryptParams();
		
		if(
			!isset($credentials['access_key'])
			|| !isset($credentials['secret_key'])
			|| !is_array($headers)
		)
			return false;
		
		if(false == ($url_parts = parse_url($url)))
			return false;
		
		$date_iso_8601 = gmdate('Ymd\THis\Z');
		
		$headers = [];
		
		if(!isset($header_keys['host']))
			$headers[] = 'Host: ' . $url_parts['host'];
		
		// Derive service + region from URL
		$matches = [];
		$service = $region = null;
		
		if(preg_match('#^(.*?)\.(.*?)\.amazonaws\.com$#', $url_parts['host'], $matches)) {
			$service = DevblocksPlatform::strLower($matches[1]);
			$region = DevblocksPlatform::strLower($matches[2]);
			
		} else if(preg_match('#^(.*?)\.amazonaws\.com$#', $url_parts['host'], $matches)) {
			$service = $matches[1];
			$region = 'us-east-1';
		}
		
		// Overload the verb
		$verb = 'GET';
		
		if(empty($region) || empty($service))
			return false;
		
		$credential_scope = sprintf("%s/%s/%s/aws4_request",
			gmdate("Ymd"),
			$region,
			$service
		);
		
		$query_parts = [];
		
		$canonical_path = $this->_createCanonicalPath($url_parts);
		$canonical_headers = $this->_createCanonicalHeaders($headers);
		$signed_headers = $this->_createSignedHeaders($headers);
		
		// [TODO] If body was JSON, else unsigned body
		
		$json = json_decode($body, true);
		
		foreach($json as $k => $v)
			$query_parts[$k] = $json[$k];
		
		$query_parts['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
		$query_parts['X-Amz-Credential'] = sprintf("%s/%s",
			$credentials['access_key'],
			$credential_scope
		);
		$query_parts['X-Amz-Date'] = $date_iso_8601;
		$query_parts['X-Amz-Expires'] = $expires_secs;
		$query_parts['X-Amz-SignedHeaders'] = $signed_headers;
		
		if(!isset($url_parts['query'])) {
			$url_parts['query'] = http_build_query($query_parts, null, '&', PHP_QUERY_RFC3986);
		} else {
			$url_parts['query'] .= '&' . http_build_query($query_parts, null, '&', PHP_QUERY_RFC3986);
		}
		
		$canonical_query = $this->_createCanonicalQueryString($url_parts);
		
		$canonical_string = 
			DevblocksPlatform::strUpper($verb) . "\n" .
			$canonical_path . "\n" .
			$canonical_query . "\n" .
			$canonical_headers . "\n" .
			$signed_headers . "\n" .
			DevblocksPlatform::strLower(hash('sha256', ''))
			;
		
		$string_to_sign = 
			'AWS4-HMAC-SHA256' . "\n" .
			$date_iso_8601 . "\n" .
			$credential_scope . "\n" .
			DevblocksPlatform::strLower(hash('sha256', $canonical_string))
			;
		
		$secret = $credentials['secret_key'];
		$hash_date = hash_hmac('sha256', gmdate('Ymd'), 'AWS4' . $secret, true);
		$hash_region = hash_hmac('sha256', $region, $hash_date, true);
		$hash_service = hash_hmac('sha256', $service, $hash_region, true);
		$hash_signing = hash_hmac('sha256', 'aws4_request', $hash_service, true);
		
		$signature = hash_hmac('sha256', $string_to_sign, $hash_signing, false);
		
		return sprintf("%s://%s%s?%s&X-Amz-Signature=%s",
			$url_parts['scheme'],
			$url_parts['host'],
			$url_parts['path'],
			$url_parts['query'],
			$signature
		);
	}
}

class BotAction_AwsGetPresignedUrl extends Extension_DevblocksEventAction {
	const ID = 'wgm.aws.bot.action.get_presigned_url';
	
	function render(Extension_DevblocksEvent $event, Model_TriggerEvent $trigger, $params=array(), $seq=null) {
		$tpl = DevblocksPlatform::getTemplateService();
		$tpl->assign('params', $params);
		
		$active_worker = CerberusApplication::getActiveWorker();
		
		if(!is_null($seq))
			$tpl->assign('namePrefix', 'action'.$seq);
		
		$aws_accounts = DAO_ConnectedAccount::getReadableByActor($trigger->getBot(), ServiceProvider_Aws::ID);
		$tpl->assign('aws_accounts', $aws_accounts);
		
		$tpl->display('devblocks:wgm.aws::bots/_action_aws_get_presigned_url.tpl');
	}
	
	function simulate($token, Model_TriggerEvent $trigger, $params, DevblocksDictionaryDelegate $dict) {
		$tpl_builder = DevblocksPlatform::getTemplateBuilder();
		
		$out = null;
		
		@$http_verb = $params['http_verb'];
		@$http_url = $tpl_builder->build($params['http_url'], $dict);
		@$http_headers = DevblocksPlatform::parseCrlfString($tpl_builder->build($params['http_headers'], $dict));
		@$http_body = $tpl_builder->build($params['http_body'], $dict);
		@$connected_account_id = $params['auth_connected_account_id'];
		@$response_placeholder = $params['response_placeholder'];
		@$expires_secs = $params['expires_secs'];
		
		if(empty($http_verb))
			return "[ERROR] HTTP verb is required.";
		
		if(empty($http_url))
			return "[ERROR] HTTP URL is required.";
		
		if(empty($response_placeholder))
			return "[ERROR] No result placeholder given.";
		
		// Output
		$out = sprintf(">>> Generating a pre-signed AWS URL for:\n%s %s\n%s%s\n",
			mb_convert_case($http_verb, MB_CASE_UPPER),
			$http_url,
			!empty($http_headers) ? (implode("\n", $http_headers)."\n") : '',
			(in_array($http_verb, array('post','put')) ? ("\n" . $http_body. "\n") : "")
		);
		
		// [TODO] Bail out on missing account
		if(false == ($connected_account = DAO_ConnectedAccount::get($connected_account_id)))
			return "[ERROR] Missing authentication account.";
		
		$out .= sprintf(">>> Authenticating with %s\n\n", $connected_account->name);
		
		$out .= sprintf(">>> Saving pre-signed URL to {{%1\$s}}:\n",
			$response_placeholder
		);
		
		$this->run($token, $trigger, $params, $dict);
		
		// [TODO] Handle errors
		$signed_url = $dict->$response_placeholder;
		
		$out .= $signed_url . "\n";
		
		/*
		if(isset($response['error']) && !empty($response['error'])) {
			$out .= sprintf(">>> Error in response:\n%s\n", $response['error']);
		}
		*/
		
		return $out;
	}
	
	function run($token, Model_TriggerEvent $trigger, $params, DevblocksDictionaryDelegate $dict) {
		$tpl_builder = DevblocksPlatform::getTemplateBuilder();

		@$http_verb = $params['http_verb'];
		@$http_url = $tpl_builder->build($params['http_url'], $dict);
		@$http_headers = DevblocksPlatform::parseCrlfString($tpl_builder->build($params['http_headers'], $dict));
		@$http_body = $tpl_builder->build($params['http_body'], $dict);
		@$response_placeholder = $params['response_placeholder'];
		@$expires_secs = $params['expires_secs'];
		
		if(empty($http_verb) || empty($http_url))
			return false;
		
		if(empty($response_placeholder))
			return false;
		
		@$connected_account_id = intval($params['auth_connected_account_id']);
		
		if(empty($connected_account_id))
			return false;
		
		$signed_url = $this->_sign_url($http_verb, $http_url, array(), $http_body, $http_headers, $connected_account_id, $expires_secs);
		$dict->$response_placeholder = $signed_url;
	}
	
	private function _sign_url($verb='get', $url, $params=array(), $body=null, $headers=array(), $connected_account_id, $expires_secs=300) {
		if(!empty($params) && is_array($params))
			$url .= '?' . http_build_query($params);
		
		$ch = DevblocksPlatform::curlInit($url);
		
		switch(DevblocksPlatform::strLower($verb)) {
			case 'get':
				break;
				
			case 'post':
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
				break;
				
			case 'put':
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
				break;
				
			case 'delete':
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
				break;
		}

		if(false == ($connected_account = DAO_ConnectedAccount::get($connected_account_id)))
			return false;
		
		// [TODO] Make sure we're authorized to use this connected account
		//if(false == (Context_ConnectedAccount::isReadableByActor($models, $actor)))
		
		$aws = new ServiceProvider_Aws();
		$signed_url = $aws->generatePresignedUrl($connected_account, $ch, $verb, $url, $body, $headers, $expires_secs);
		
		curl_close($ch);
		
		return $signed_url;
	}
};