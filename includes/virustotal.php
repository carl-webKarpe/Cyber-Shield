<?php
declare(strict_types=1);

/**
 * Cyber-Shield VirusTotal API v3 client.
 * All requests are made server-side so the API key never reaches a browser or agent.
 */
final class CyberShieldVirusTotalException extends RuntimeException
{
    public int $httpStatus;

    public function __construct(string $message, int $httpStatus = 0)
    {
        parent::__construct($message);
        $this->httpStatus = $httpStatus;
    }
}

final class CyberShieldVirusTotal
{
    private string $apiKey;
    private string $baseUrl;

    public function __construct(string $apiKey, string $baseUrl = 'https://www.virustotal.com/api/v3')
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        if (trim($apiKey) === '') {
            throw new CyberShieldVirusTotalException('VirusTotal is not configured. Add virustotal_api_key to config.local.php.');
        }
        $this->apiKey = trim($apiKey);
    }

    public static function fromConfig(): self
    {
        return new self((string) cs_config('virustotal_api_key'), (string) cs_config('virustotal_api_base'));
    }

    /** Returns the file report, or null when VirusTotal has never seen this hash. */
    public function getFileReport(string $hash): ?array
    {
        return $this->request('GET', '/files/' . rawurlencode(strtolower($hash)), null, true);
    }

    /** Uploads a file for analysis and returns the analysis id. */
    public function uploadFile(string $path, string $fileName): string
    {
        $endpoint = '/files';
        if (filesize($path) > 32 * 1024 * 1024) {
            $uploadUrl = $this->request('GET', '/files/upload_url');
            $endpoint = (string) ($uploadUrl['data'] ?? '');
            if ($endpoint === '') {
                throw new CyberShieldVirusTotalException('VirusTotal did not return an upload URL for a large file.');
            }
        }
        $response = $this->request('POST', $endpoint, ['file' => new CURLFile($path, 'application/octet-stream', $fileName)]);
        $analysisId = (string) ($response['data']['id'] ?? '');
        if ($analysisId === '') {
            throw new CyberShieldVirusTotalException('VirusTotal accepted the upload but returned no analysis id.');
        }
        return $analysisId;
    }

    public function getAnalysis(string $analysisId): array
    {
        return $this->request('GET', '/analyses/' . rawurlencode($analysisId));
    }

    /** Returns the URL report, or null when VirusTotal has never analysed this URL. */
    public function getUrlReport(string $url): ?array
    {
        return $this->request('GET', '/urls/' . self::urlId($url), null, true);
    }

    public function submitUrl(string $url): string
    {
        $response = $this->request('POST', '/urls', http_build_query(['url' => $url]));
        $analysisId = (string) ($response['data']['id'] ?? '');
        if ($analysisId === '') {
            throw new CyberShieldVirusTotalException('VirusTotal accepted the URL but returned no analysis id.');
        }
        return $analysisId;
    }

    public static function urlId(string $url): string
    {
        return rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
    }

    /**
     * @param array|string|null $body array = multipart upload, string = form-encoded body
     */
    private function request(string $method, string $endpoint, $body = null, bool $allowNotFound = false): ?array
    {
        $url = preg_match('#^https?://#', $endpoint) ? $endpoint : $this->baseUrl . $endpoint;
        $curl = curl_init($url);
        $headers = ['x-apikey: ' . $this->apiKey, 'accept: application/json'];
        if (is_string($body)) {
            $headers[] = 'content-type: application/x-www-form-urlencoded';
        }
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => is_array($body) ? 300 : 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if ($body !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        $raw = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);

        if ($raw === false) {
            throw new CyberShieldVirusTotalException('Could not reach VirusTotal: ' . $curlError);
        }
        $data = json_decode((string) $raw, true);
        if ($status === 404 && $allowNotFound) {
            return null;
        }
        if ($status >= 200 && $status < 300 && is_array($data)) {
            return $data;
        }
        $message = $data['error']['message'] ?? ('VirusTotal returned HTTP ' . $status . '.');
        if ($status === 401) {
            $message = 'VirusTotal rejected the API key. Check virustotal_api_key in config.local.php.';
        } elseif ($status === 429) {
            $message = 'VirusTotal rate limit reached (public keys allow 4 requests per minute). Try again shortly.';
        }
        throw new CyberShieldVirusTotalException($message, $status);
    }
}
