package backends

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	jwtGo "github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
)

type goJWTChecker struct {
	pubCertRsa      *rsa.PublicKey
	pubCertRsaPath  string
	privCertHMAC    []byte
	issuerURL       string
	kid             string
	options         tokenOptions
	allowedRoles    string
	allowedIssuer   string
	allowedAudience string
	parsedToken     *jwtGo.Token
}

func NewGoBckChecker(authOpts map[string]string, options tokenOptions) (jwtChecker, error) {
	checker := &goJWTChecker{
		options: options,
	}
	//kid to load the public certificate
	if kid, ok := authOpts["jwt_go_kid"]; ok {
		checker.kid = kid
	} else {
		log.Debug("please specify kid")
		return nil, fmt.Errorf("not specified kid")
	}
	//public certificate path has to be in the pem format
	if pubCertPath, ok := authOpts["jwt_go_pubcert_path_RSA"]; ok {
		log.Debugf("Path given to go-auth: -> " + pubCertPath)
		data, err := os.ReadFile(pubCertPath)
		if err != nil {
			log.Debugf("Error during file reading %s", err)
			return nil, err
		}
		//converting string gain from file to *rsa.PublicKey format
		pubCertConverted, err := StringToRSAPublicKey(data)
		if err != nil {
			log.Debugf("Error in certificate conversion %s", err)
			return nil, err
		} else {
			checker.pubCertRsa = pubCertConverted
		}
	}
	//
	if privateKeypath, ok := authOpts["jwt_go_privcert_path_HMAC"]; ok {
		log.Debugf("Path given to go-auth: -> " + privateKeypath)
		data, err := os.ReadFile(privateKeypath)
		if err != nil {
			log.Debugf("Error during file reading %s", err)
			return nil, err
		} else {
			checker.privCertHMAC = data
		}
	}
	//path to public certificate
	if link, ok := authOpts["jwt_go_public_cert_link"]; ok {
		if checker.pubCertRsa == nil && checker.pubCertRsaPath == "" {
			checker.issuerURL = link
			//execute the code if the public cert is empty
			if checker.kid == "" {
				log.Debug("kid empty")
				return nil, fmt.Errorf("kid emplty")
			}
			pubCertExtracted, err := getPubCertFromURL(link, checker.kid)
			if err != nil {
				return nil, fmt.Errorf("error during public cert extracting")
			}
			checker.pubCertRsa = pubCertExtracted
		} else {
			log.Debug("pubCertrsa already decoded or pubCertRsaPath specified")
			return nil, fmt.Errorf("pubCertrsa already decoded or pubCertRsaPath specified")
		}

	}
	//kid value to extract the key
	if checker.pubCertRsa == nil {
		return nil, fmt.Errorf("empty public certificate")
	}

	//allowed role from token claims
	if roles, ok := authOpts["jwt_go_allowed_role"]; ok {
		checker.allowedRoles = roles
	} else {
		log.Debug("please specify allowed rules")
		return nil, fmt.Errorf("not specified rule")
	}
	//allowed issuer
	if iss, ok := authOpts["jwt_go_allowed_iss"]; ok {
		checker.allowedIssuer = iss
	} else {
		log.Debug("please specify Iss")
		return nil, fmt.Errorf("not specified iss")
	}
	return checker, nil
}

func (o *goJWTChecker) GetSuperuser(token string) (bool, error) {
	return false, nil
}

func (o *goJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	return true, nil
}

func (o *goJWTChecker) GetUser(token string) (bool, error) {
	//params := map[string]interface{}{
	//	"token": token,
	//}
	valid, err := o.VerifyJWTSignature(token, o.pubCertRsa, o.privCertHMAC)
	if err != nil || valid == false {
		log.Debugf("go error : #{err}")
		return false, err
	}
	parsed, err := o.CheckClaims()
	return parsed, err
}

func (o *goJWTChecker) Halt() {
	// NO-OP
}

// VerifyJWTSignature Function to check if the signature is valid
func (o *goJWTChecker) VerifyJWTSignature(tokenStr string, publicKey *rsa.PublicKey, privKey []byte) (bool, error) {
	// Parse the token
	token, err := jwtGo.Parse(tokenStr, func(token *jwtGo.Token) (interface{}, error) {
		// Check the sign method
		if _, ok := token.Method.(*jwtGo.SigningMethodRSA); ok {
			log.Debugf("Signing method RSA")
			return publicKey, nil
		}
		return nil, fmt.Errorf("sign method not valid")
	})

	if err != nil {
		return false, fmt.Errorf("parsting token error: %v", err)
	}

	// check the token if valid
	if token.Valid {

		o.parsedToken = token
		return true, nil
	} else {
		return false, fmt.Errorf("non valid Token")
	}

}

// StringToRSAPublicKey returns *rsa.PublicKey type variable
func StringToRSAPublicKey(publicKeyStr []byte) (*rsa.PublicKey, error) {
	// Parse the PEM pub key
	block, _ := pem.Decode(publicKeyStr)
	if block == nil {
		return nil, fmt.Errorf("error decoding public key")
	}
	// Public key parsing
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Debug("error during public key parsing:", err)
		return nil, err
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	//fmt.Println("Rsa Pub Key N", rsaPublicKey.N)
	//fmt.Println("Rsa Pub Key E", rsaPublicKey.E)
	return rsaPublicKey, nil
}

// CheckClaims check if claims are ok like iss and user role
func (o *goJWTChecker) CheckClaims() (bool, error) {
	var claims jwtGo.MapClaims
	var ok bool
	if claims, ok = o.parsedToken.Claims.(jwtGo.MapClaims); ok {
		if iss, ok := claims["iss"].(string); ok {
			if iss == o.allowedIssuer {
				log.Debug("iss claim ok")
			} else {
				log.Debug("iss claim ! ok")
				return false, nil
			}
		} else {
			log.Debug("iss claim not a string")
		}
		if aud, ok := claims["aud"].(string); ok {
			if aud == o.allowedAudience {
				log.Debug("audience ok")
			} else {
				log.Debug("oudience ! ok")
				return false, fmt.Errorf("not allowed audience")
			}
		}
	} else {
		log.Debug("unable to access claim field")
	}
	if custom, ok := claims["custom"].(map[string]interface{}); ok {
		if rules, ok := custom["rules"].([]interface{}); ok {
			found := false
			for _, r := range rules {
				if r == o.allowedRoles {
					found = true
					log.Debug("user role found")
					return found, nil
				}
			}
			if !found {
				log.Debug("user user role not found")
				return found, nil
			}
		} else {
			log.Debug("rules claim not found")
			return false, fmt.Errorf("rules claim not found")
		}
	} else {
		log.Debug("custom claim not found")
		return false, fmt.Errorf("custom claim not found")
	}

	return false, fmt.Errorf("unpredict exit")
}

// MainJSON main structure of cloudflare JSON
type MainJSON struct {
	Keys        []keys       `json:"keys"`
	PublicCert  publicCert   `json:"public_cert"`
	PublicCerts []publicCert `json:"public_certs"`
}

// structure of keys field
type keys struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
}

// structure of both publicCert fields
type publicCert struct {
	Kid  string `json:"kid"`
	Cert string `json:"cert"`
}

// get a public certificate from a JSON via URL
func getPubCertFromURL(url string, kid string) (*rsa.PublicKey, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error during get request")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(response.Body)

	//read body response
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error during response resding %e", err)
	}

	//decode message body
	var DecodedJson MainJSON
	err = json.Unmarshal(body, &DecodedJson)
	if err != nil {
		return nil, fmt.Errorf("error during message decoding %e", err)
	}
	//fmt.Println(DecodedJson)

	//extract the public key from the selected kid
	for _, certs := range DecodedJson.PublicCerts {
		if certs.Kid == kid {
			//returns the public key requested and the error from the called function
			return StringToRSAPublicKey([]byte(certs.Cert))
		}
	}
	return nil, fmt.Errorf("error kid not found")
}
