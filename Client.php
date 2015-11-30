<?php

namespace phpcent;

/**
 * Class centrifuge php driver
 * User: komrakov
 * Date: 02.04.2015 12:30
 *
 * @version 1.1
 */
class Client
{

    protected $guzzle;
    protected $hashing_algorithm;
    protected $api_url;
    protected $secret;

    public function __construct(array $options = [])
    {
        $this->guzzle            = isset($options['guzzle'])            ? $options['guzzle']            : new \GuzzleHttp\Client();
        $this->hashing_algorithm = isset($options['hashing_algorithm']) ? $options['hashing_algorithm'] : "sha256";
        $this->api_url           = isset($options['api_url'])           ? $options['api_url']           : "http://localhost:8000/api/";
        $this->secret            = isset($options['secret'])            ? $options['secret']            : "";
    }

    public function publish($channel, $data, $client = "")
    {
        $request = [
            'method' => 'publish',
            'params' => [
                'channel' => $channel,
                'data'    => $data,
            ],
        ];
        if (!empty($client)) {
            $request['params']['client'] = $client;
        }

        return $this->request($request);
    }

    /**
     * @param string $channel
     * @param string $user_id
     *
     * @return array
     */
    public function unsubscribe($channel, $user_id)
    {
        $request = [
            'method' => 'unsubscribe',
            'params' => [
                'channel' => $channel,
                'user'    => $user_id,
            ],
        ];

        return $this->request($request);
    }

    /**
     * @param string $user_id
     *
     * @return array
     */
    public function disconnect($user_id)
    {
        $request = [
            'method' => 'disconnect',
            'params' => [
                'user' => $user_id,
            ],
        ];

        return $this->request($request);
    }

    /**
     * @param string $channel
     *
     * @return array
     */
    public function presence($channel)
    {
        $request = [
            'method' => 'presence',
            'params' => [
                'channel' => $channel,
            ],
        ];

        return $this->request($request);
    }

    /**
     * @param string $channel
     *
     * @return array
     */
    public function history($channel)
    {
        $request = [
            'method' => 'history',
            'params' => [
                'channel' => $channel,
            ],
        ];

        return $this->request($request);
    }

    /**
     * @return array
     */
    public function channels()
    {
        $request = [
            'method' => 'channels',
            'params' => [],
        ];

        return $this->request($request);
    }

    /**
     * @return array
     */
    public function stats()
    {
        $request = [
            'method' => 'stats',
            'params' => [],
        ];

        return $this->request($request);
    }

    /**
     * @param $request
     *
     * @return array
     * @throws \Exception
     */
    public function request($request)
    {
        $encoded_data = json_encode($request);
        $sign = $this->generateApiSign($this->secret, $encoded_data);
        $body = $this->guzzle->post($this->api_url, ['form_params' => ['sign' => $sign, 'data' => $encoded_data]])->getBody();
        $result = json_decode($body, true);
        if (!isset($result[0])) {
            throw new \Exception("Invalid response format");
        }

        return $result[0];
    }

    /**
     * @param \GuzzleHttp\Client $guzzle
     */
    public function setGuzzle($guzzle)
    {
        $this->guzzle = $guzzle;
    }

    /**
     * @param string $hashing_algorithm
     */
    public function setHashingAlgorithm($hashing_algorithm)
    {
        $this->hashing_algorithm = $hashing_algorithm;
    }

    /**
     * @param string $api_url
     */
    public function setApiUrl($api_url)
    {
        $this->api_url = $api_url;
    }

    /**
     * @param string $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * When client connects to Centrifuge from browser it should provide several
     * connection parameters: "user", "timestamp", "info" and "token".
     *
     * @link https://fzambia.gitbooks.io/centrifugal/content/server/tokens_and_signatures.html
     *
     * @param $secret
     * @param $user
     * @param $timestamp
     * @param string $info
     *
     * @return string
     */
    public function generateToken($secret, $user, $timestamp, $info = "")
    {
        $context = hash_init($this->hashing_algorithm, HASH_HMAC, $secret);
        hash_update($context, $user);
        hash_update($context, $timestamp);
        hash_update($context, $info);

        return hash_final($context);
    }

    /**
     * When client wants to subscribe on private channel Centrifuge
     * js client sends AJAX POST request to your web application.
     * This request contains client ID string and one or multiple private channels.
     * In response you should return an object where channels are keys.
     *
     * @link https://fzambia.gitbooks.io/centrifugal/content/server/tokens_and_signatures.html
     *
     * @param $secret
     * @param $client
     * @param string $channel
     * @param string $info
     *
     * @return string
     */
    public function generateChannelSign($secret, $client, $channel, $info = "")
    {
        $context = hash_init($this->hashing_algorithm, HASH_HMAC, $secret);
        hash_update($context, $client);
        hash_update($context, $channel);
        hash_update($context, $info);

        return hash_final($context);
    }

    /**
     * When you use Centrifugo server API you should also provide sign in each request.
     *
     * @link https://fzambia.gitbooks.io/centrifugal/content/server/tokens_and_signatures.html
     *
     * @param $secret
     * @param $encoded_data
     *
     * @return string
     */
    public function generateApiSign($secret, $encoded_data)
    {
        $context = hash_init($this->hashing_algorithm, HASH_HMAC, $secret);
        hash_update($context, $encoded_data);

        return hash_final($context);
    }

}