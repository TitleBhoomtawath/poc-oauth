package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"
	"github.com/deliveryhero/mystiko-go"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	hmacKey = "hZbjMQJX8nTEDNo4irRIpQf74I1H0N1Jl8WVqIqnm6gpKkjSefN+qwX4zC2K15BlLVc2tduoWJBdEQrF9KrX8A=="
	appID   = "ops-portal-pd-corporate-api"
)

// TokenRequestBodyDTO request body for exchanging code for access token
type TokenRequestBodyDTO struct {
	Scope     string `json:"scope"`
	Code      string `json:"code"`
	clientID  string
	grantType string
}

// TokenErrorMetaDTO meta data explaining an error
type TokenErrorMetaDTO struct {
	Description string `json:"description"`
}

// TokenErrorResponseBodyDTO error response
type TokenErrorResponseBodyDTO struct {
	Status string            `json:"status"`
	Code   string            `json:"code"`
	Title  string            `json:"title"`
	Meta   TokenErrorMetaDTO `json:"meta"`
}

// TokenResponseBodyDTO response body from IAM Service
type TokenResponseBodyDTO struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func ExchangeWithIAM(code string) (*oauth2.Token, error) {
	formData := url.Values{
		"client_id":  {appID},
		"grant_type": {"authorization_code"},
		"code":       {code},
		//"scope":      {"application.ops-portal-pd-corporate-api namespace.ops-portal-pd-corporate-api"},
	}
	reqBody := formData.Encode()
	logger.Log.Info("request body: " + reqBody)
	req, err := mystiko.NewHMACRequest(http.MethodPost, "https://iam-st.dh-auth.io/api/v1/oauth2/token", strings.NewReader(reqBody), appID, []byte(hmacKey))
	//if err != nil {
	//	return nil, err
	//}
	//hmacHeaders, err := NewHMACHeaders(http.MethodPost, "/api/v1/oauth2/token", []byte(reqBody), appID, []byte(hmacKey), time.Now().UTC().Format(time.RFC850))
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Printf("is auth match %v", hmacHeaders.Authorization == req.Header.Get("Authorization"))
	//req, err := http.NewRequest(http.MethodPost, "https://iam-st.dh-auth.io/api/v1/oauth2/token", strings.NewReader(formData.Encode()))
	//if err != nil {
	//	return nil, err
	//}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("Date", hmacHeaders.Date)
	//req.Header.Set("X-DHH-Date", hmacHeaders.XDHHDate)
	//req.Header.Set("Authorization", hmacHeaders.Authorization)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		token := &oauth2.Token{}
		err = json.Unmarshal(body, &token)
		if err != nil {
			return nil, err
		}

		return token, nil
	}
	errorResponse := TokenErrorResponseBodyDTO{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &errorResponse); err != nil {
		return nil, err
	}
	logger.Log.Error("Error reason: " + errorResponse.Meta.Description)
	return nil, errors.New(errorResponse.Meta.Description)
}

func CallBackToIAM(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	logger.Log.Info(code)
	//code = "4/0AX4XfWjX_AL97tJZo8cKSW7KP6TXuiRwuPIEutXzR_nHu4iyyVn0VrT8dCWsxhqrQ3LpUA"

	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := ExchangeWithIAM(code)
		if err != nil {
			logger.Log.Error("ExchangeWithIAM failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
		if err != nil {
			logger.Log.Error("Get: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Log.Error("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		logger.Log.Info("parseResponseBody: " + string(response) + "\n")

		w.Write([]byte("Hello, I'm protected\n"))
		w.Write([]byte(string(response)))
		return
	}
}

type HMACHeaders struct {
	Authorization string
	Date          string
	XDHHDate      string
}

// NewHMACHeaders returns a Headers required for HMAC authentication
func NewHMACHeaders(method string, rurl string, body []byte, applicationID string, hmacKey []byte, ts string) (HMACHeaders, error) {
	var (
		err     error
		headers HMACHeaders
	)

	_, err = url.Parse(rurl)
	if err != nil {
		return headers, err
	}

	hash := hmac.New(sha256.New, hmacKey)
	if err != nil {
		return headers, err
	}

	if _, err = io.WriteString(hash, method); err != nil {
		return headers, err
	}
	if _, err = io.WriteString(hash, rurl); err != nil {
		return headers, err
	}
	if _, err = io.WriteString(hash, ts); err != nil {
		return headers, err
	}

	if _, err := hash.Write(body); err != nil {
		return headers, err
	}

	sum := hash.Sum(nil)

	signature := []byte(fmt.Sprintf("%s:%s", applicationID, base64.StdEncoding.EncodeToString(sum)))
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	headers = HMACHeaders{
		Authorization: fmt.Sprintf("HMAC %s", encodedSignature),
		Date:          ts,
		XDHHDate:      ts,
	}
	return headers, nil
}

// NewHMACRequest returns an http.Request that signs the request with the passed key
func NewHMACRequest(method string, rurl string, body io.Reader, keyID string, key []byte, ts string) (*http.Request, error) {
	var (
		err error
		req *http.Request
	)

	_, err = url.Parse(rurl)
	if err != nil {
		return nil, err
	}

	hash := hmac.New(sha256.New, key)
	if body != nil {
		tr := io.TeeReader(body, hash)
		req, err = http.NewRequest(method, rurl, tr)
	} else {
		req, err = http.NewRequest(method, rurl, nil)
	}
	if err != nil {
		return nil, err
	}

	_, _ = io.WriteString(hash, req.Method)
	_, _ = io.WriteString(hash, ExtractPath(req.URL))
	_, _ = io.WriteString(hash, ts)
	_, _ = httputil.DumpRequest(req, true)

	sum := hash.Sum(nil)

	signature := []byte(fmt.Sprintf("%s:%s", keyID, base64.StdEncoding.EncodeToString(sum)))
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	req.Header.Set("Authorization", fmt.Sprintf("HMAC %s", encodedSignature))
	req.Header.Set("Date", ts)
	req.Header.Set("X-DHH-Date", ts)

	return req, nil
}

func ExtractPath(rurl *url.URL) string {
	path := rurl.Path
	query := rurl.Query().Encode()
	ret := ""

	if path == "" {
		ret = "/"
	} else {
		ret = path
	}

	if query != "" {
		ret += "?" + query
	}

	return ret
}

// HMACVerifier is a function that gets a request and verifies the request
// This type is used mainly to abstract the return value of HMAC.Verifier
type HMACVerifier func(ctx context.Context, r *http.Request) (string, error)

var (
	ErrVerificationFailed     = errors.New("Request verification failed")
	ErrNoAuthHeader           = errors.New("No Authorization header")
	ErrWrongSignatureEncoding = errors.New("Wrong signature encoding")
	ErrUnverifiedRequest      = errors.New("Unverified request")
	ErrRequestExpired         = errors.New("Request expired")
)
