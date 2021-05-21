<?php
/*******************************************************************************
 * Copyright (c) 2015  DjAlex88 (https://github.com/djalex88/)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *******************************************************************************/

defined('_JEXEC') or die;

class PlgSystemDigest extends JPlugin
{
	public function __construct(&$subject, $config = array())
	{
		parent::__construct($subject, $config);

		$this->app = JFactory::getApplication();
		$this->session = JFactory::getSession();
	}

	public function onAfterInitialise()
	{
		if($this->app->isSite())
		{
			return; // only for backend
		}

		// load parameters

		$this->realm = trim($this->params->get('realm', ''));
		if($this->realm === '')
		{
			$this->realm = 'administrator@' . JUri::getInstance()->getHost();
		}

		$this->nonce_lifetime = (int) $this->params->get('nonce_lifetime', 300);
		if($this->nonce_lifetime < 30)
		{
			$this->nonce_lifetime = 300; // set default
		}

		// check authentication header

		if(isset($_SERVER['PHP_AUTH_DIGEST']) and $this->authenticate())
		{
			return; // Ok
		}

		$this->sendAuthHeader(); // require authentication
	}

	protected function generateNonce()
	{
		return base64_encode(random_bytes(30));
	}

	protected function sendAuthHeader()
	{
		// generate nonce and store in session

		$nonce = $this->generateNonce();
		$nonceTime = time();

		$this->session->set('digest_auth_nonce', $nonce);
		$this->session->set('digest_auth_nonce_time', $nonceTime);
		$this->session->set('digest_auth_nc', 0);

		// send WWW-Authenticate header

		header('HTTP/1.1 401 Unauthorized');
		header('WWW-Authenticate: Digest realm="' . $this->realm .
       		'", domain="' . JUri::base() . '", qop="auth", nonce="' . $nonce . '"');

		$this->terminate("Authorization required!");
	}

	protected function parseAuthHeader(&$data)
	{
		$authHeader = $_SERVER['PHP_AUTH_DIGEST'];

		if(!preg_match('#username="([^"]+)"#', $authHeader, $match)) return false;
		$data['username'] = $match[1];

		if(!preg_match('#realm="'.$this->realm.'"#', $authHeader)) return false;
		$data['realm'] = $this->realm;

		if(!preg_match('#nonce="([[:ascii:]][^"]+)"#', $authHeader, $match)) return false;
		$data['nonce'] = $match[1];

		if(!preg_match('#uri="([[:ascii:][:^cntrl:]][^\s"]*)"#', $authHeader, $match)) return false;
		$data['uri'] = $match[1];

		if(!preg_match('#response="([[:xdigit:]]{32})"#', $authHeader, $match)) return false;
		$data['response'] = $match[1];

		if(!preg_match('#qop=auth#', $authHeader)) return false;
		$data['qop'] = 'auth';

		if(!preg_match('#nc=([[:xdigit:]]{8})#', $authHeader, $match)) return false;
		$data['nc'] = $match[1];

		if(!preg_match('#cnonce="([[:ascii:]][^"]+)"#', $authHeader, $match)) return false;
		$data['cnonce'] = $match[1];

		return true;
	}

	protected function authenticate()
	{
		// try to extract data from PHP_AUTH_DIGEST string

		if(!$this->parseAuthHeader($data))
		{
			return false;
		}

		// get the nonce assigned to the client

		$nonce = $this->session->get('digest_auth_nonce');
		$nonceTime = $this->session->get('digest_auth_nonce_time');
		$nc = $this->session->get('digest_auth_nc');

		if(!$nonce or ($data['nonce'] !== $nonce) or (intval($data['nc'], 16) <= $nc))
		{
			return false;
		}

		// get user's credentials

		$dbo = JFactory::getDbo();

		$query = $dbo->getQuery(true)
			->select($dbo->quoteName(array('id', 'username')))
			->from($dbo->quoteName('#__users'))
			->where($dbo->quoteName('username') . ' = ' . $dbo->quote($data['username']));

		$user = $dbo->setQuery($query)->loadObject();
		if(!$user)
		{
			return false; // user does not exist
		}

		// get user's password for digest authentication

		$passwordFile = trim($this->params->get('password_file', ''));
		if($passwordFile === '' or !is_file($passwordFile))
		{
			$passwordFile = __DIR__ . '/passwords.php';
		}
		if((include $passwordFile) == false or !array_key_exists($user->username, $passwords))
		{
			return false; // eihter password file does not exist, or no password
		}

		$user->password = $passwords[$user->username];

		//
		// compute valid response and check
		//

		$A1 = $user->username.':'.$this->realm.':'.$user->password;
		$A2 = $_SERVER['REQUEST_METHOD'].':'.$data['uri'];
		$validResponse = md5(md5($A1).':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.md5($A2));

		if($data['response'] !== $validResponse)
		{
			return false;
		}

		// ok
		// good response

		$time = time();

		if($time > $nonceTime + $this->nonce_lifetime)
		{
			// it's time to renew the nonce
			// assign new nonce and request reauthentication

			$nonce = $this->generateNonce();

			$this->session->set('digest_auth_nonce', $nonce);
			$this->session->set('digest_auth_nonce_time', $time);
			$this->session->set('digest_auth_nc', 0);

			// make the client reauthenticate automatically (stale=TRUE)

			header('HTTP/1.1 401 Unauthorized');
			header('WWW-Authenticate: Digest realm="' . $this->realm .
	       		'", domain="' . JUri::base() . '", qop="auth", stale=TRUE, nonce="' . $nonce . '"');

			$this->terminate("Authentication error!");
		}
		else
		{
			// update nc (nonce count)
			$this->session->set('digest_auth_nc', intval($data['nc'], 16));
		}

		// one more step:
		// Joomla's authentication (if configured)

		if(JFactory::getUser()->get('guest') == 1)
		{
			$this->app->login(
				array(
					'username' => $user->username,
					'password' => $user->password,
				),
				array(
					'silent' => true,
				)
			);
		}

		return true;
	}

	protected function terminate($text)
	{
		$html = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>$text</title>
</head>
<body>
	<div style="
			position: fixed;
			top: 50%;
			width: 100%;
			height: 0;
			overflow: visible;
		">
		<div style="
				position: absolute;
				bottom: 0;
				width: 100%;
				text-align: center;
			">
			<span style="
					display: inline-block;
					padding: 0.25em 1em;
					background-color: maroon;
					color: white;
				">
					$text
			</span>
		</div>
	</div>
</body>
</html>
HTML;
		echo $html;

		$this->app->close();
	}

} // PlgSystemDigest

