<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

use Config;

class ShogakukanAccount001 extends AbstractService
{
    /**
     * Facebook www url - used to build dialog urls
     */
    const WWW_URL = 'http://dev-oauth.sho.co.jp/';

    /**
     * Defined scopes
     *
     * If you don't think this is scary you should not be allowed on the web at all
     *
     * @link https://developers.facebook.com/docs/reference/login/
     * @link https://developers.facebook.com/tools/explorer For a list of permissions use 'Get Access Token'
     */
    // Email scopes
    const SCOPE_EMAIL                         = 'email';
    // Extended scopes
    const SCOPE_PESONAL_INFORMATION           = 'personal';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            if (Config::has('oauth.domain')) {
                $this->baseApiUri = new Uri(config('oauth.domain'));
            } else {
                $this->baseApiUri = new Uri('http://dev-oauth.sho.co.jp/');
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        if (Config::has('oauth.domain')) {
            return new Uri(config('oauth.domain'). 'oauth/authorize');
        } else {
            return new Uri('http://dev-oauth.sho.co.jp/oauth/authorize');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        if (Config::has('oauth.domain')) {
            return new Uri(config('oauth.domain'). 'oauth/access_token');
        } else {
            return new Uri('http://dev-oauth.sho.co.jp/oauth/access_token');
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        // Github tokens evidently never expire...
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getScopesDelimiter()
    {
        return ',';
    }
}
