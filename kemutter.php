<?php
/**
 * Kemutter - PHP Library for Twitter API
 *
 * @version 1.0.0
 * @author Kemuridama <kemuridama@kemuridama.net>
 * @copyright Copyright (C) 2014 Kemuridama All rights reserved.
 */

class Kemutter
{
	/**
	 * Define Twitter API URLs
	 * @see https://dev.twitter.com/oauth
	 */
	const REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token';
	const ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token';
	const AUTHENTICATE_URL = 'https://api.twitter.com/oauth/authenticate';
	const AUTHORIZE_URL = 'https://api.twitter.com/oauth/authorize';

	/**
	 * Consumer token
	 * @var string
	 */
	private $consumer_key;

	/**
	 * Consumer secret
	 * @var string
	 */
	private $consumer_secret;

	/**
	 * Access token
	 * @var string
	 */
	private $access_token;

	/**
	 * Access token secret
	 * @var string
	 */
	private $access_token_secret;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param string $consumer_key
	 * @param string $consumer_secret
	 * @param string $access_token
	 * @param string $access_token_secret
	 */
	public function __construct($consumer_key, $consumer_secret, $access_token = null, $access_token_secret = null)
	{
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->access_token = $access_token;
		$this->access_token_secret = $access_token_secret;
	}

	/**
	 * Get the request token
	 *
	 * @access public
	 * @param string $callback_url
	 * @return string
	 */
	public function getRequestToken($callback_url = null)
	{
		$parameters = is_null($callback_url) ? array() : array('oauth_callback', $callback_url);
		return $this->request('POST', static::REQUEST_TOKEN_URL, $parameters);
	}

	/**
	 * Get the authorize URL
	 *
	 * @access public
	 * @param string $request_token
	 * @param bool $sign_in_with_twitter
	 * @return string
	 */
	public function getAuthorizeUrl($request_token, $sign_in_with_twitter = false)
	{
		if ($sign_in_with_twitter) {
			return static::AUTHORIZE_URL . '?oauth_token=' . $request_token;
		} else {
			return static::AUTHENTICATE_URL . '?oauth_token=' . $request_token;
		}
	}

	/**
	 * Get the access token
	 *
	 * @access public
	 * @param string $oauth_verifier
	 * @return array
	 */
	public function getAccessToken($oauth_verifier)
	{
		$parameters = array('oauth_verifier' => $oauth_verifier);
		return $this->request('POST', static::ACCESS_TOKEN_URL, $parameters);
	}

	/**
	 * Request the Twitter API
	 *
	 * @access public
	 * @param string $method
	 * @param string $url
	 * @param array $parameters
	 * @return array
	 */
	public function request($method, $url, array $parameters = array())
	{
		// Generate the OAuth parameters
		$oauth_parameters = array(
			'oauth_consumer_key' => $this->consumer_key,
			'oauth_nonce' => md5(microtime() . mt_rand()),
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => time(),
			'oauth_version' => '1.0'
		);

		// Check access token exists and add the access token to the OAuth parameters
		is_null($this->access_token) or $oauth_parameters['oauth_token'] = $this->access_token;

		// Add the signature to the OAuth parameters
		$oauth_parameters['oauth_signature'] = $this->calculateSignature($method, $url, $oauth_parameters, $parameters);

		// Setup the cURL session
		$curl_session = curl_init();
		curl_setopt($curl_session, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($curl_session, CURLOPT_TIMEOUT, 30);
		curl_setopt($curl_session, CURLOPT_HTTPHEADER, array('Authorization: OAuth ' . http_build_query($oauth_parameters, '', ', ', PHP_QUERY_RFC3986)));
		curl_setopt($curl_session, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl_session, CURLOPT_HEADER, false);

		$parameters = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
		if ($method == 'POST') {
			curl_setopt($curl_session, CURLOPT_POST, true);
			isset($parameters) and curl_setopt($curl_session, CURLOPT_POSTFIELDS, $parameters);
		} else {
			$url .= '?' . $parameters;
		}

		// Execute the cURL session
		curl_setopt($curl_session, CURLOPT_URL, $url);
		$curl_response = curl_exec($curl_session);
		if (!$curl_response) {
			throw new KemutterException('Kemutter: cURL error', 1);
		}

		if (stripos($url, '.json') !== false) {
			// Decode the result of JSON format and fetch the Twitter API errors
			$response = json_decode($curl_response, true);
			if (is_null($response)) {
				throw new KemutterException('Kemutter: Return response of JSON format is empty or broken', 2);
			} elseif (array_key_exists('errors', $response)) {
				throw new KemutterException('Twitter API: ' . $response['errors'][0]['message'], $response['errors'][0]['code']);
			}
		} else {
			// Parse the result of string
			parse_str($curl_response, $response);
			if (empty($response)) {
				throw new KemutterException('Kemutter: Return response of string is empty', 3);
			}
		}

		return $response;
	}

	/**
	 * Calculate the signature
	 *
	 * @access private
	 * @param string $method
	 * @param string $url
	 * @param array $parameters
	 * @param array $oauth_parameters
	 * @return string
	 */
	private function calculateSignature($method, $url, $oauth_parameters, array $parameters = array())
	{
		// Merge and sort parameters for creating the signature
		$signature_parameters = array_merge($parameters, $oauth_parameters);
		ksort($signature_parameters);

		// Generate the base string and the signing key
		$base_string = implode('&', array(rawurlencode($method), rawurlencode($url), rawurlencode(http_build_query($signature_parameters, '', '&', PHP_QUERY_RFC3986))));
		$signing_key = implode('&', array(rawurlencode($this->consumer_secret), rawurlencode($this->access_token_secret)));

		return base64_encode(hash_hmac('sha1', $base_string, $signing_key, true));
	}
}

class KemutterException extends Exception {}
