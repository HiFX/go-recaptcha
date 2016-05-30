//Package recaptcha provides an easy function to verify Google's ReCaptcha on the server side.
package recaptcha

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

//ReCaptcha verification URL
const apiURL = "https://www.google.com/recaptcha/api/siteverify"

//API Response from Google
type apiResponse struct {
	Success    bool
	ErrorCodes []string `json:"error-codes"`
}

//Recaptcha is returned by the New function. It contains the verify function
type Recaptcha struct {
	//Private key for ReCaptcha. Will be set when calling the New function with the secret as the parameter
	privateKey string
}

//New function creates and returns Recaptcha instance after setting the private key.
//The parameter private key is the ReCaptcha private key obtained from Google
func New(privateKey string) *Recaptcha {
	return &Recaptcha{privateKey}
}

//Verify function verifies the Captcha with the Google servers.
//First parameter gRecaptchaResponse is the value obtained from the 'g-recaptcha-response' in the form.
//clientIP is optional
func (rec *Recaptcha) Verify(gRecaptchaResponse, clientIP string) (bool, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	var requestParams map[string][]string

	if clientIP != "" {
		requestParams = url.Values{"secret": {rec.privateKey}, "response": {gRecaptchaResponse}, "remoteip": {clientIP}}
	} else {
		requestParams = url.Values{"secret": {rec.privateKey}, "response": {gRecaptchaResponse}}
	}

	resp, err := client.PostForm(apiURL, requestParams)

	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	res := apiResponse{}
	err = json.Unmarshal(body, res)
	if err != nil {
		return false, err
	}
	if res.Success {
		return res.Success, nil
	}

	if len(res.ErrorCodes) > 0 {
		return false, errors.New(res.ErrorCodes[0])
	}
	return true, nil
}
