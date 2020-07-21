# qbhy/hyperf-testing
该扩展包可以提供和 `laravel` 几乎一致的测试用例书写体验

## 安装 - install
```bash
$ composer require qbhy/hyperf-testing
```

## 使用 - usage
1. 修改 `HyperfTest\HttpTestCase` 的 `$client`，把默认的 `Client` 改成 `Qbhy\HyperfTesting\Client`
2. 修改测试用例
```php
<?php

namespace HyperfTest\Cases\Dev;

use HyperfTest\HttpTestCase;
use Qbhy\HyperfTesting\Client;
use Qbhy\HyperfTesting\TestResponse;

/**
 * Class DevTest
 * @method TestResponse get($uri, $data = [], $headers = [])
 * @method TestResponse post($uri, $data = [], $headers = [])
 * @method TestResponse delete($uri, $data = [], $headers = [])
 * @method TestResponse put($uri, $data = [], $headers = [])
 * @method TestResponse json($uri, $data = [], $headers = [])
 * @method TestResponse file($uri, $data = [], $headers = [])
 * @package HyperfTest\Cases\Dev
 */
class DevTest extends HttpTestCase
{
    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->client = make(Client::class);
    }

    public function testExample()
    {
        $this->get('/')->assertOk()->assertJsonStructure([
            'data', 'code', 'message',
        ]);
    }
}
```
> 暂不支持 cookie 和 session 相关的断言！

## 声明 - statement
该包大量参考了 laravel 的代码。感谢 laravel 实现了那么好用的测试用例组件。

https://github.com/qbhy/hyperf-testing  
96qbhy@qq.com
