<?php
/**
 * SimpleEmailServiceRequest PHP class
 *
 * @link https://github.com/daniel-zahariev/php-aws-ses
 * @version 0.8.3
 * @package AmazonSimpleEmailService
 */

namespace yashop\ses\libs;

final class SimpleEmailServiceRequest
{
    const SERVICE = 'email';
    const ALGORITHM = 'AWS4-HMAC-SHA256';

    private $ses, $verb, $parameters = array();
    public $response;
    public static $curlOptions = array();

    /**
     * Constructor
     *
     * @param string $ses The SimpleEmailService object making this request
     * @param string $action action
     * @param string $verb HTTP verb
     * @param array $curl_options Additional cURL options
     * @return mixed
     */
    function __construct($ses, $verb)
    {
        $this->ses = $ses;
        $this->verb = $verb;
        $this->response = new \stdClass();
        $this->response->error = false;
        $this->response->body = '';
    }

    /**
     * Set request parameter
     *
     * @param string $key Key
     * @param string $value Value
     * @param boolean $replace Whether to replace the key if it already exists (default true)
     * @return void
     */
    public function setParameter($key, $value, $replace = true)
    {
        if (!$replace && isset($this->parameters[$key])) {
            $temp = (array)($this->parameters[$key]);
            $temp[] = $value;
            $this->parameters[$key] = $temp;
        } else {
            $this->parameters[$key] = $value;
        }
    }

    /**
     * Get the response
     *
     * @return object | false
     */
    public function getResponse()
    {
        $headers = array();

        $params = $this->parameters;
        ksort($params);

        $date = gmdate('Ymd');
        $amzDate = gmdate('Ymd\THis\Z');
        $canonicalURI = '/';
        $queryParameters = '';
        $canonicalHeaders = '';
        $signedHeaders = '';
        $queryParams = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        $headers[] = 'Host: ' . $this->ses->getHost();
        if (in_array($this->parameters['Action'], ['SendRawEmail', 'SendEmail'])) {
            $canonicalHeaders .= 'content-type:' . 'application/x-www-form-urlencoded' . "\n";
            $signedHeaders .= 'content-type;';
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        } else {
            $query_parameters = $queryParams;
        }

        $canonicalHeaders .= 'host:' . $this->ses->getHost() . "\n" . 'x-amz-date:' . $amzDate . "\n";
        $signedHeaders .= 'host;x-amz-date';
        $payloadHash = hash('sha256', $queryParams);

        // task1
        $canonical_request =
            $this->verb . "\n" .
            $canonicalURI . "\n" .
            $queryParameters . "\n" .
            $canonicalHeaders . "\n" .
            $signedHeaders . "\n" .
            $payloadHash;

        // task2
        $credential_scope = $date . '/' . $this->ses->getRegion() . '/' . self::SERVICE . '/aws4_request';
        $string_to_sign =
            self::ALGORITHM . "\n" .
            $amzDate . "\n" .
            $credential_scope . "\n" .
            hash('sha256', $canonical_request);

        // task3
        $signingKey = $this->_generateSignature($date, $this->ses->getRegion(), $this->ses->getSecretKey());
        $signature = hash_hmac('sha256', $string_to_sign, $signingKey);
        $headers[] = 'Authorization: ' . self::ALGORITHM . ' Credential=' . $this->ses->getAccessKey() . '/' . $credential_scope . ', SignedHeaders=' . $signedHeaders . ', Signature=' . $signature;
        $headers[] = 'x-amz-date: ' . $amzDate;

        $url = 'https://' . $this->ses->getHost() . '/';

        // Basic setup
        $curl = $this->ses->getCurl();

        if ($curl === true) {
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
            $this->ses->setCurl($curl);
        }

        if (!$curl) {
            $curl = curl_init();
        }

        curl_setopt($curl, CURLOPT_USERAGENT, 'SimpleEmailService/php');

        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, ($this->ses->verifyHost() ? 2 : 0));
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, ($this->ses->verifyPeer() ? 1 : 0));

        // Request types
        switch ($this->verb) {
            case 'GET':
                $url .= '?' . $queryParams;
                break;
            case 'POST':
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $this->verb);
                curl_setopt($curl, CURLOPT_POSTFIELDS, $queryParams);
                break;
            case 'DELETE':
                $url .= '?' . $queryParams;
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
            default:
                break;
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_HEADER, false);

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($curl, CURLOPT_WRITEFUNCTION, array(&$this, '__responseWriteCallback'));
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);

        foreach (self::$curlOptions as $option => $value) {
            curl_setopt($curl, $option, $value);
        }

        // Execute, grab errors
        if (curl_exec($curl)) {
            $this->response->code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        } else {
            $this->response->error = array(
                'curl' => true,
                'code' => curl_errno($curl),
                'message' => curl_error($curl),
                'resource' => $this->resource
            );
        }

        if (!$this->ses->getCurl()) {
            @curl_close($curl);
        }

        // Parse body into XML
        if ($this->response->error === false && isset($this->response->body)) {
            $this->response->body = simplexml_load_string($this->response->body);

            // Grab SES errors
            if (!in_array($this->response->code, array(200, 201, 202, 204))
                && isset($this->response->body->Error)) {
                $error = $this->response->body->Error;
                $output = array();
                $output['curl'] = false;
                $output['Error'] = array();
                $output['Error']['Type'] = (string)$error->Type;
                $output['Error']['Code'] = (string)$error->Code;
                $output['Error']['Message'] = (string)$error->Message;
                $output['RequestId'] = (string)$this->response->body->RequestId;

                $this->response->error = $output;
                unset($this->response->body);
            }
        }

        return $this->response;
    }

    /**
     * CURL write callback
     *
     * @param resource &$curl CURL resource
     * @param string &$data Data
     * @return integer
     */
    private function __responseWriteCallback(&$curl, &$data)
    {
        $this->response->body .= $data;
        return strlen($data);
    }

    private function _generateSignature($date, $region, $awsSecret)
    {
        $dateHash = hash_hmac('sha256', $date, 'AWS4' . $awsSecret, true);
        $regionHash = hash_hmac('sha256', $region, $dateHash, true);
        $serviceHash = hash_hmac('sha256', self::SERVICE, $regionHash, true);
        return hash_hmac('sha256', 'aws4_request', $serviceHash, true);
    }
}
