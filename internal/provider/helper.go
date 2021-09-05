package provider

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func request(client *ApiClient, method string, resource string,  body io.Reader) (responseCode int, response []byte, err error) {
	httpClient := &http.Client{}
	url := fmt.Sprintf("%s/%s", client.apiEndpoint, resource)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	bodyForSignature := bytes.NewReader([]byte{})

	if req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return http.StatusBadRequest, nil, err
		}

		bodyForSignature = bytes.NewReader(b)
	}

	_, err = client.signer.Sign(req, bodyForSignature, "execute-api", client.region, time.Now())
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	f, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	return resp.StatusCode, f, nil
}