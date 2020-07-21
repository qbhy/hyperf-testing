<?php


namespace Qbhy\HyperfTesting;


use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Trait ResponseTrait
 * @package Qbhy\HyperfTesting
 * @property-read ResponseInterface $baseResponse
 */
trait ResponseTrait
{
    /**
     * @return ResponseInterface
     */
    public function getBaseResponse(): ResponseInterface
    {
        return $this->baseResponse;
    }

    /**
     * Retrieves the status code for the current web response.
     *
     * @final
     */
    public function getStatusCode(): int
    {
        return $this->baseResponse->getStatusCode();
    }

    /**
     * Is response successful?
     *
     * @final
     */
    public function isSuccessful(): bool
    {
        return $this->getStatusCode() >= 200 && $this->getStatusCode() < 300;
    }

    /**
     * Is the response OK?
     *
     * @final
     */
    public function isOk(): bool
    {
        return 200 === $this->getStatusCode();
    }

    /**
     * Gets the current response content.
     *
     * @return string|false
     */
    public function getContent()
    {
        return $this->baseResponse->getBody()->__toString();
    }

    /**
     * Is the response a not found error?
     *
     * @final
     */
    public function isNotFound(): bool
    {
        return 404 === $this->getStatusCode();
    }

    /**
     * Is the response forbidden?
     *
     * @final
     */
    public function isForbidden(): bool
    {
        return 403 === $this->getStatusCode();
    }

    /**
     * Is the response a redirect of some form?
     *
     * @final
     */
    public function isRedirect(string $location = null): bool
    {
        return \in_array($this->getStatusCode(), [201, 301, 302, 303, 307, 308]) && (null === $location ?: $location == $this->baseResponse->getHeader('Location'));
    }

    /**
     * Is the response empty?
     *
     * @final
     */
    public function isEmpty(): bool
    {
        return \in_array($this->getStatusCode(), [204, 304]);
    }

    /**
     * Sends content for the current web response.
     *
     * @return $this
     */
    public function sendContent()
    {
        echo $this->getContent();

        return $this;
    }
}