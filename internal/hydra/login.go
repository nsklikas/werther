/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package hydra

import (
	"context"

	hClient "github.com/ory/hydra-client-go/v2"
	"github.com/pkg/errors"
)

// LoginReqDoer fetches information on the OAuth2 request and then accept or reject the requested authentication process.
type LoginReqDoer struct {
	hydraURL           string
	hydra              Client
	fakeTLSTermination bool
	rememberFor        int
}

// NewLoginReqDoer creates a LoginRequest.
func NewLoginReqDoer(hydraURL string, fakeTLSTermination bool, rememberFor int) *LoginReqDoer {
	r := &LoginReqDoer{hydraURL: hydraURL, fakeTLSTermination: fakeTLSTermination, rememberFor: rememberFor}
	r.hydra = *NewClient(hydraURL, true)
	return r
}

// InitiateRequest fetches information on the OAuth2 request.
func (lrd *LoginReqDoer) InitiateRequest(challenge string) (*ReqInfo, error) {
	ctx := context.Background()
	lr, _, err := lrd.hydra.c.OAuth2API.
		GetOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		Execute()
	ri := new(ReqInfo)
	ri.Challenge = lr.Challenge
	ri.RequestedAudience = lr.RequestedAccessTokenAudience
	ri.RequestedScopes = lr.RequestedScope
	ri.Skip = lr.Skip
	ri.Subject = lr.Subject
	return ri, errors.Wrap(err, "failed to initiate login request")
}

// AcceptLoginRequest accepts the requested authentication process, and returns redirect URI.
func (lrd *LoginReqDoer) AcceptLoginRequest(challenge string, remember bool, subject string) (string, error) {
	ctx := context.Background()
	accept := hClient.NewAcceptOAuth2LoginRequest(subject)
	accept.SetRemember(remember)
	accept.SetRememberFor(int64(lrd.rememberFor))
	redirectURI, _, err := lrd.hydra.OAuth2API().
		AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(challenge).
		AcceptOAuth2LoginRequest(*accept).
		Execute()

	if err != nil {
		return "", err
	}

	return redirectURI.RedirectTo, errors.Wrap(err, "failed to accept login request")
}
