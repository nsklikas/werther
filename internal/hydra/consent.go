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

// ConsentReqDoer fetches information on the OAuth2 request and then accept or reject the requested authentication process.
type ConsentReqDoer struct {
	hydraURL           string
	hydra              Client
	fakeTLSTermination bool
	rememberFor        int
}

// NewConsentReqDoer creates a ConsentRequest.
func NewConsentReqDoer(hydraURL string, fakeTLSTermination bool, rememberFor int) *ConsentReqDoer {
	r := &ConsentReqDoer{hydraURL: hydraURL, fakeTLSTermination: fakeTLSTermination, rememberFor: rememberFor}
	r.hydra = *NewClient(hydraURL, true)
	return r
}

// InitiateRequest fetches information on the OAuth2 request.
func (crd *ConsentReqDoer) InitiateRequest(challenge string) (*ReqInfo, error) {
	cr, _, err := crd.hydra.OAuth2API().
		GetOAuth2ConsentRequest(context.Background()).
		ConsentChallenge(challenge).
		Execute()
	ri := new(ReqInfo)
	ri.Challenge = cr.Challenge
	ri.RequestedAudience = cr.RequestedAccessTokenAudience
	ri.RequestedScopes = cr.RequestedScope
	ri.Skip = *cr.Skip
	ri.Subject = *cr.Subject
	return ri, errors.Wrap(err, "failed to initiate consent request")
}

// AcceptConsentRequest accepts the requested authentication process, and returns redirect URI.
func (crd *ConsentReqDoer) AcceptConsentRequest(challenge string, remember bool, grantScope []string, grantAudience []string, idToken interface{}) (string, error) {
	session := hClient.NewAcceptOAuth2ConsentRequestSession()
	session.SetIdToken(idToken)

	r := hClient.NewAcceptOAuth2ConsentRequest()
	r.SetGrantScope(grantScope)
	r.SetGrantAccessTokenAudience(grantAudience)
	r.SetRemember(remember)
	r.SetRememberFor(int64(crd.rememberFor))
	r.SetSession(*session)

	accept, _, err := crd.hydra.OAuth2API().
		AcceptOAuth2ConsentRequest(context.Background()).
		ConsentChallenge(challenge).
		AcceptOAuth2ConsentRequest(*r).
		Execute()

	return accept.RedirectTo, errors.Wrap(err, "failed to accept consent request")
}
