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
	"time"

	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type OAuthIAMConf struct {
	ClientID  string
	HMACKey   string
	AuthURL   string
	AppID     string
	Namespace string
}

var oauthIAMConf = &OAuthIAMConf{}

// InitializeOAuthIAM initialize IAM
func InitializeOAuthIAM() {
	oauthIAMConf.ClientID = viper.GetString("iam.clientID")
	oauthIAMConf.AuthURL = viper.GetString("iam.authURL")
	oauthIAMConf.AppID = viper.GetString("iam.appID")
	oauthIAMConf.HMACKey = viper.GetString("iam.hmacKey")
	oauthIAMConf.Namespace = viper.GetString("iam.namespace")
}

// AuthenticationResponse response structure
type AuthenticationResponse struct {
	AccessToken  string `json:"access_token"`
	Expiry       string `json:"expiry"`
	RefreshToken string `json:"refresh_token"`
}

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
		"client_id":  {oauthIAMConf.AppID},
		"grant_type": {"authorization_code"},
		"code":       {code},
		"scope":      {"application." + oauthIAMConf.AppID + " namespace." + oauthIAMConf.Namespace},
	}
	reqBody := formData.Encode()
	decodedHMAC, err := base64.StdEncoding.DecodeString(oauthIAMConf.HMACKey)
	if err != nil {
		return nil, err
	}

	hmacHeaders, err := NewHMACHeaders(http.MethodPost, "/api/v1/oauth2/token", []byte(reqBody), oauthIAMConf.AppID, decodedHMAC, time.Now().UTC().Format(time.RFC850))
	logger.Log.Info(fmt.Sprintf("HMAC header %s", hmacHeaders.Authorization))
	logger.Log.Info(fmt.Sprintf("X-DHH-Date %s", hmacHeaders.XDHHDate))
	if err != nil {
		return nil, err
	}
	//fmt.Printf("is auth match %v", hmacHeaders.Authorization == req.Header.Get("Authorization"))
	req, err := http.NewRequest(http.MethodPost, oauthIAMConf.AuthURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Date", hmacHeaders.Date)
	req.Header.Set("X-DHH-Date", hmacHeaders.XDHHDate)
	req.Header.Set("Authorization", hmacHeaders.Authorization)

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
		err = json.Unmarshal(body, token)
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

type IAMLoginRequest struct {
	Token string `json:"token"`
}

func HandleIAMLogin(w http.ResponseWriter, r *http.Request) {
	setupHeader(w, r)
	if r.Method == http.MethodPost {
		var iamReq IAMLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&iamReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}

		fmt.Println(iamReq.Token)
		token, err := ExchangeWithIAM(iamReq.Token)
		if err != nil {
			logger.Log.Error("ExchangeWithIAM failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		respPayload := AuthenticationResponse{
			AccessToken:  token.AccessToken,
			Expiry:       token.Expiry.String(),
			RefreshToken: token.RefreshToken,
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(respPayload)

		return
	}
}

func CallBackToIAM(w http.ResponseWriter, r *http.Request) {
	setupHeader(w, r)
	//code := r.FormValue("code")
	r.ParseForm()
	form := r.Form
	code := form.Get("code")
	logger.Log.Info(code)

	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := ExchangeWithIAM(code)
		if err != nil {
			logger.Log.Error("ExchangeWithIAM failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)
		respPayload := AuthenticationResponse{
			AccessToken:  token.AccessToken,
			Expiry:       token.Expiry.String(),
			RefreshToken: token.RefreshToken,
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(respPayload)
		return
	}
}

type HMACHeaders struct {
	Authorization string
	Date          string
	XDHHDate      string
}

func setupHeader(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	rw.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
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
	logger.Log.Info(fmt.Sprintf("Authorization header: %s", fmt.Sprintf("HMAC %s", encodedSignature)))
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
