<?php
/**
 * Class centrifuge php driver
 * User: sl4mmer
 * Date: 02.04.2015 12:30
 *
 * @version 0.7
 */

namespace phpcent;


class Client
{
    private $host;
    private $secretKey;
    private $projectId;

    /**
     * @var ITransport $transport
     */
    private $transport;

    /**
     * @param string $host
     */
    public function __construct($host = "http://localhost:8000")
    {
        $this->host = $host;
    }

    public function getHost()
    {
        return $this->host;
    }

    /**
     * Set project details
     *
     * @param string $project_id
     * @param string $secret_key
     * @return $this
     */
    public function setProject($project_id, $secret_key)
    {
        $this->projectId = $project_id;
        $this->secretKey = $secret_key;
        return $this;
    }

    /**
     * send message into channel of namespace. data is an actual information you want to send into channel
     * @param $channel
     * @param array $data
     * @return mixed
     */
    public function publish($channel, $data = [])
    {
        return $this->send("publish", ["channel" => $channel, "data" => $data]);
    }

    /**
     * unsubscribe user with certain ID from channel.
     * @param $channel
     * @param $userId
     * @return mixed
     */
    public function unsubscribe($channel, $userId)
    {
        return $this->send("unsubscribe", ["channel" => $channel, "user" => $userId]);
    }

    /**
     * disconnect user by user ID.
     * @param $userId
     * @return mixed
     */
    public function disconnect($userId)
    {
        return $this->send("disconnect", ["user" => $userId]);
    }

    /**
     * get channel presence information (all clients currently subscribed on this channel).
     * @param $channel
     * @return mixed
     */
    public function presence($channel)
    {
        return $this->send("presence", ["channel" => $channel]);
    }

    /**
     * get channel history information (list of last messages sent into channel).
     * @param $channel
     * @return mixed
     */
    public function history($channel)
    {
        return $this->send("presence", ["channel" => $channel]);
    }

    /**
     * @param string $method
     * @param array $params
     * @return mixed
     * @throws \Exception
     */
    public function send($method, $params = [])
    {
        if (empty($params))
            $params = new \StdClass();

        try {
            $data   = json_encode(["method" => $method, "params" => $params]);
            $result = $this->getTransport()->communicate($this->host, $this->projectId, ["data" => $data, "sign" => $this->generateApiSign($data)]);

        } catch (\Exception $exception){
            throw $exception;
        }

        return $result;
    }

    /**
     * Generate connection token
     *
     * @link http://centrifuge.readthedocs.org/en/latest/content/tokens_and_signatures.html?highlight=token
     *
     * @param string $user_id
     * @param string $timestamp
     * @param null $info
     * @return string
     */
    public function generateToken($user_id, $timestamp, $info = Null)
    {
        $this->checkKeys();

        $ctx = hash_init("sha256", HASH_HMAC, $this->secretKey);
        hash_update($ctx, $this->projectId);
        hash_update($ctx, $user_id);
        hash_update($ctx, $timestamp);
        hash_update($ctx, !empty($info) ? json_encode($info) : "");

        return hash_final($ctx);
    }

    /**
     * Generate sign for Api requests
     *
     * @param string $encoded_data
     * @return string
     */
    public function generateApiSign($encoded_data)
    {
        $this->checkKeys();

        $ctx = hash_init("sha256", HASH_HMAC, $this->secretKey);
        hash_update($ctx, $this->projectId);
        hash_update($ctx, $encoded_data);
        return hash_final($ctx);
    }

    /**
     * @param string $client_id
     * @param string $channel
     * @param null $info
     * @return string
     */
    public function generateChannelSigh($client_id, $channel, $info = Null)
    {
        $this->checkKeys();

        $ctx = hash_init("sha256", HASH_HMAC, $this->secretKey);
        hash_update($ctx, $client_id);
        hash_update($ctx, $channel);
        hash_update($ctx, !empty($info) ? json_encode($info) : "");

        return hash_final($ctx);
    }

    /**
     * @return ITransport
     */
    private function getTransport()
    {
        if ($this->transport == null)
            $this->setTransport(new Transport());

        return $this->transport;
    }

    /**
     * @param ITransport $transport
     */
    public function setTransport(ITransport $transport)
    {
        $this->transport = $transport;
    }

    /**
     * Check internal project and secret key
     * @throws \Exception
     */
    private function checkKeys()
    {
        if ($this->secretKey == null)
            throw new \Exception("Project key should not be empty");

        if ($this->projectId == null)
            throw new \Exception("Project id should not be empty");
    }

}
