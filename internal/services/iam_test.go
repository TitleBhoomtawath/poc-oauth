package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	base64Key = "aFpiak1RSlg4blRFRE5vNGlyUklwUWY3NEkxSDBOMUpsOFdWcUlxbm02Z3BLa2pTZWZOK3F3WDR6QzJLMTVCbExWYzJ0ZHVvV0pCZEVRckY5S3JYOEE9PQ=="
)

func TestNewHMACRequest(t *testing.T) {
	formData := url.Values{
		"client_id":  {appID},
		"grant_type": {"authorization_code"},
		"code":       {"code"},
		"scope":      {"application.ops-portal-pd-corporate-api namespace.ops-portal-pd-corporate-api"},
	}
	reqBody := formData.Encode()
	//ts := "Wednesday, 22-Dec-21 07:18:32 UTC"
	ts := time.Now().UTC().Format(time.RFC850)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		verifier := Verifier()
		unsafedSignature, err := verifier(context.Background(), r)
		assert.NoError(t, err)
		assert.Equal(t, appID, unsafedSignature)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer svr.Close()

	req, err := NewHMACRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/oauth2/token", svr.URL), strings.NewReader(reqBody), appID, []byte(hmacKey), ts)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	assert.NoError(t, err)
	client := http.Client{}
	_, err = client.Do(req)

	assert.NoError(t, err)
}

func TestNewHMACHeaders(t *testing.T) {
	formData := url.Values{
		"client_id":  {appID},
		"grant_type": {"authorization_code"},
		"code":       {"code"},
		"scope":      {"application.ops-portal-pd-corporate-api namespace.ops-portal-pd-corporate-api"},
	}
	reqBody := formData.Encode()
	//ts := "Wednesday, 22-Dec-21 07:18:32 UTC"
	ts := time.Now().UTC().Format(time.RFC850)
	headers, err := NewHMACHeaders(http.MethodPost, "/api/v1/oauth2/token", []byte(reqBody), appID, []byte(hmacKey), ts)
	assert.NoError(t, err)

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		verifier := Verifier()
		unsafedSignature, err := verifier(context.Background(), r)
		assert.NoError(t, err)
		assert.Equal(t, appID, unsafedSignature)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer svr.Close()

	req, err := http.NewRequest(http.MethodPost, "https://iam-st.dh-auth.io/api/v1/oauth2/token", strings.NewReader(formData.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Date", headers.Date)
	req.Header.Set("X-DHH-Date", headers.XDHHDate)
	req.Header.Set("Authorization", headers.Authorization)

	client := http.Client{}
	_, err = client.Do(req)
	assert.NoError(t, err)
}

func TestNewHMACHeadersMatchNewHMACRequests(t *testing.T) {
	formData := url.Values{
		"client_id":  {appID},
		"grant_type": {"authorization_code"},
		"code":       {"code"},
		"scope":      {"application.ops-portal-pd-corporate-api namespace.ops-portal-pd-corporate-api"},
	}
	reqBody := formData.Encode()
	ts := time.Now().UTC().Format(time.RFC850)
	rawHMACKey := []byte(hmacKey)
	headers, err := NewHMACHeaders(http.MethodPost, "/api/v1/oauth2/token", []byte(reqBody), appID, rawHMACKey, ts)
	assert.NoError(t, err)

	req, err := NewHMACRequest(http.MethodPost, "https://iam-st.dh-auth.io/api/v1/oauth2/token", strings.NewReader(reqBody), appID, rawHMACKey, ts)

	assert.Equal(t, req.Header.Get("Authorization"), headers.Authorization)
}

func keyProvider() ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Key)
}

// Verifier creates a function that verifies that the request contains a proper key/signature pair and
// that the signature is the expected one.
// To generate the signature we use the following piece of data
//
//     * method:    The method of the request (in uppercase)
//     * path:      This is actually the URL now.
//     * timestamp: The timestamp that goes into the Date (or X-MRV-Date) header. It should be
//                  formatted in one of the formats that can be parsed by http.ParseTime (TimeFormat, time.RFC850,
//                  and time.ANSIC)
//     * body:      The body of the request (for verbs that support body)
//
// and we sign it with SHA-256 with the secret key that corresponds
// to the ID the caller gave us.
func Verifier() HMACVerifier {
	return func(ctx context.Context, r *http.Request) (string, error) {
		var (
			providedSignature []byte
			unsafeAPIKey      string
			strRequestTime    string
		)
		authHeader := r.Header.Get("Authorization")
		authParts := strings.Split(authHeader, " ")
		if len(authParts) == 2 && authParts[0] == "HMAC" {
			auth, err := base64.StdEncoding.DecodeString(authParts[1])
			if err == nil {
				authParts = strings.Split(string(auth), ":")
				if len(authParts) == 2 {
					unsafeAPIKey = authParts[0]
					providedSignature, err = base64.StdEncoding.DecodeString(authParts[1])
					if err != nil {
						return "", ErrWrongSignatureEncoding
					}
				}
			} else {
				return "", ErrNoAuthHeader
			}
		}

		strRequestTime = r.Header.Get("Date")
		if strRequestTime == "" {
			strRequestTime = r.Header.Get("X-DHH-Date")
		}

		if strRequestTime == "" {
			return "", ErrRequestExpired
		}

		validUntil := -1 * 15 * time.Minute
		requestTime, err := http.ParseTime(strRequestTime)
		if requestTime.Before(time.Now().Add(validUntil)) || err != nil {
			return "", ErrRequestExpired
		}
		secretKey, err := keyProvider()
		if err != nil {
			return "", err
		}
		buf := bytes.NewBufferString("")

		if _, err := io.WriteString(buf, r.Method); err != nil {
			return "", ErrVerificationFailed
		}

		path := r.URL.Path
		if _, err := io.WriteString(buf, path); err != nil {
			return "", ErrVerificationFailed
		}

		if strRequestTime != "" {
			if _, err := io.WriteString(buf, strRequestTime); err != nil {
				return "", ErrVerificationFailed
			}
		}

		if !(r.Method == "GET" || r.Method == "DELETE" || r.Method == "HEAD") {
			if r.Body == nil {
				return "", ErrVerificationFailed
			}
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return "", ErrVerificationFailed
			}

			if _, err := buf.Write(body); err != nil {
				return "", ErrVerificationFailed
			}
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
		expected := hmac.New(sha256.New, secretKey)
		expected.Write(buf.Bytes())
		expectedSignature := expected.Sum(nil)
		if hmac.Equal(expectedSignature, providedSignature) {
			return unsafeAPIKey, nil
		}

		return "", ErrUnverifiedRequest
	}
}
