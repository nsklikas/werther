package hydra

import (
	hClient "github.com/ory/hydra-client-go/v2"
)

type Client struct {
	c *hClient.APIClient
}

func (c *Client) OAuth2API() hClient.OAuth2API {
	return c.c.OAuth2API
}

func (c *Client) MetadataAPI() hClient.MetadataAPI {
	return c.c.MetadataAPI
}

func NewClient(url string, debug bool) *Client {
	c := new(Client)

	configuration := hClient.NewConfiguration()
	configuration.Debug = debug
	configuration.Servers = []hClient.ServerConfiguration{
		{
			URL: url,
		},
	}

	c.c = hClient.NewAPIClient(configuration)

	return c
}
