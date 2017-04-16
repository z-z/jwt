<?php

class Jwt
{
    private $header;
    private $use_ip;
    private $key;

    /**
     * Jwt constructor.
     * @param $key string секретный ключ, которым подписывается токен
     * @param null $header конфигурационные данные (алгоритм шифрования alg и время жизни токена exp)
     * @param bool $use_ip использовать ли IP пользователя при создании токена
     */
    public function __construct($key, $header = null, $use_ip=true)
    {
        $this->use_ip = $use_ip;
        $this->key = $key;
        $this->header = is_array($header) ? $header : array('alg' => 'sha256', 'exp' => '+1 minutes');
    }

    /**
     * @param $payload array пользовательские данные, которые надо закодировать в токен
     * @param null $head array конфигурационные данные (алгоритм шифрования alg и время жизни токена exp)
     * @return string
     */
    public function token($payload, $head=null)
    {
        $header = is_null($head) ? $this->header : $head;
        if(gettype($header['exp']) == 'string') $header['exp'] = strtotime($header['exp']);
        $header = $this->base64url_encode($header);
        $payload = $this->base64url_encode($payload);
        $data = $header . "." . $payload;
        $signature = hash_hmac($this->header['alg'], $data, $this->secret());
        return implode('.', [$header, $payload, $signature]);
    }

    /**
     * @param $token
     * @param bool $get_header true - вернет массив header, иначе вернет массив payload
     * @return array
     */
    public function data($token, $get_header=false)
    {
        $token = explode('.', $token);
        $token = $get_header ? $token[0] : $token[1];
        return $this->base64url_decode($token);
    }

    /**
     * @param $token
     * @param $data array данные, желательно все взятые из базы, а не от клиента
     * @return mixed если токен не прошел проверку - вернет false, иначе вернет токен с обновленным временем жизни
     */
    public function validate($token, $data)
    {
        $token_parts = explode('.', $token);
        if(count($token_parts) != 3) return false;

        $head = $this->data($token, true);
        if(!array_key_exists('exp', $head)) return false;
        if($head['exp'] < time()) return false;

        $new_token = $this->token($data, $head);
        if($token !== $new_token) return false;
        else return $this->token($data);
    }

    private function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');
    }

    private function base64url_decode($data) {
        $str = base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
        return json_decode($str, true);
    }

    private function secret()
    {
        $secret = $_SERVER['HTTP_USER_AGENT'];
        if($this->use_ip) $secret .= "|" . $_SERVER['REMOTE_ADDR'];
        $secret .= "|" . $this->key;
        return $secret;
    }
}
