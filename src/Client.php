<?php


namespace Qbhy\HyperfTesting;

use Hyperf\Testing\Client as HyperfClient;
use Hyperf\Utils\Arr;

class Client extends HyperfClient
{
    public function get($uri, $data = [], $headers = [])
    {
        $response = $this->request('GET', $uri, [
            'headers' => $headers,
            'query' => $data,
        ]);

        return new TestResponse($response);
    }

    public function post($uri, $data = [], $headers = [])
    {
        $response = $this->request('POST', $uri, [
            'headers' => $headers,
            'form_params' => $data,
        ]);

        return new TestResponse($response);
    }

    public function put($uri, $data = [], $headers = [])
    {
        $response = $this->request('PUT', $uri, [
            'headers' => $headers,
            'form_params' => $data,
        ]);

        return new TestResponse($response);
    }

    public function delete($uri, $data = [], $headers = [])
    {
        $response = $this->request('DELETE', $uri, [
            'headers' => $headers,
            'query' => $data,
        ]);

        return new TestResponse($response);
    }

    public function json($uri, $data = [], $headers = [])
    {
        $headers['Content-Type'] = 'application/json';
        $response = $this->request('POST', $uri, [
            'headers' => $headers,
            'json' => $data,
        ]);
        return new TestResponse($response);
    }

    public function file($uri, $data = [], $headers = [])
    {
        $multipart = [];
        if (Arr::isAssoc($data)) {
            $data = [$data];
        }

        foreach ($data as $item) {
            $name = $item['name'];
            $file = $item['file'];

            $multipart[] = [
                'name' => $name,
                'contents' => fopen($file, 'r'),
                'filename' => basename($file),
            ];
        }

        $response = $this->request('POST', $uri, [
            'headers' => $headers,
            'multipart' => $multipart,
        ]);

        return new TestResponse($response);
    }
}