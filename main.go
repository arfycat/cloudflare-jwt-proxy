package main


import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "strings"

    "github.com/coreos/go-oidc"
    "github.com/gorilla/handlers"
)

func isTrue(value string) bool {
    return strings.EqualFold(value, "true") || value == "1"
}

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

type RequestHeader struct {
    Name string
    Value string
}

var (
    ctx        = context.TODO()
    authDomain = getEnv("AUTH_DOMAIN", "https://test.cloudflareaccess.com")
    certsURL   = fmt.Sprintf("%s/cdn-cgi/access/certs", authDomain)

    // policyAUD is your application AUD value
    policyAUD = getEnv("POLICY_AUD", "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2")
    config = &oidc.Config{
        ClientID: policyAUD,
    }

    tlsCert = getEnv("TLS_CERT", "")
    tlsKey = getEnv("TLS_KEY", "")
    listenAddress = getEnv("LISTEN_ADDRESS", "")
    listenPort = getEnv("LISTEN_PORT", "8080")
    proxyURL = getEnv("PROXY_URL", "http://default:80")
    proxyHost = getEnv("PROXY_HOST", "")
    proxyXForwardedHost = getEnv("PROXY_X_FORWARDED_HOST", "")
    proxyTLSServerName = getEnv("PROXY_TLS_SERVER_NAME", "")
    proxyTLSInsecure = getEnv("PROXY_TLS_INSECURE", "")
    proxyTLSCACert = getEnv("PROXY_TLS_CA_CERT", "")
    proxyRequestHeadersJSONFile = getEnv("PROXY_REQ_HEADERS", "")

    keySet   = oidc.NewRemoteKeySet(ctx, certsURL)
    verifier = oidc.NewVerifier(authDomain, keySet, config)

    proxyRequestHeaders []RequestHeader
)

// VerifyToken is a middleware to verify a CF Access token
func VerifyToken(next http.Handler) http.Handler {
    fn := func(w http.ResponseWriter, r *http.Request) {
        headers := r.Header

        // Make sure that the incoming request has our token header
        //  Could also look in the cookies for CF_AUTHORIZATION
        accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
        if accessJWT == "" {
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte("No token on the request"))
            return
        }

        // Verify the access token
        ctx := r.Context()
        _, err := verifier.Verify(ctx, accessJWT)
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
            return
        }
        next.ServeHTTP(w, r)
    }
    return http.HandlerFunc(fn)
}

func MainHandler() http.Handler {
    origin, _ := url.Parse(proxyURL)

    director := func(req *http.Request) {
        if proxyHost != "" {
            req.Header.Set("Host", proxyHost)
        }

        if proxyXForwardedHost != "" {
            req.Header.Set("X-Forwarded-Host", proxyXForwardedHost)
        } else {
            req.Header.Set("X-Forwarded-Host", req.Host)
        }

        req.Header.Set("X-Origin-Host", origin.Host)

        if proxyRequestHeaders != nil {
            for _, header := range proxyRequestHeaders {
                if header.Value == "" {
                    req.Header.Del(header.Name)
                } else {
                    req.Header.Set(header.Name, header.Value)
                }
            }
        }

        req.URL.Scheme = origin.Scheme
        req.URL.Host = origin.Host
    }

    proxy := &httputil.ReverseProxy{Director: director}

    tlsConfig := &tls.Config{}

    if isTrue(proxyTLSInsecure) {
        tlsConfig.InsecureSkipVerify = true
    } else {
        if proxyTLSServerName != "" {
            tlsConfig.ServerName = proxyTLSServerName
        }

        if proxyTLSCACert != "" {
            // https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
            rootCAs := x509.NewCertPool()
            certs, err := ioutil.ReadFile(proxyTLSCACert)
            if err != nil {
                log.Fatalf("Failed to append %q to RootCAs: %v", proxyTLSCACert, err)
            }

            if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
                log.Fatalf("No certs appended from file: %q", proxyTLSCACert)
            }

            tlsConfig.RootCAs = rootCAs
        }
    }

    transport := &http.Transport{}
    transport.TLSClientConfig = tlsConfig
    proxy.Transport = transport

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        proxy.ServeHTTP(w,r)
    })
}

func main() {
    if proxyRequestHeadersJSONFile != "" {
        proxyRequestHeadersJSON, err := ioutil.ReadFile(proxyRequestHeadersJSONFile)
        if err != nil {
            log.Fatalf("Failed read proxy request headers JSON file: %q, error: %v", proxyRequestHeadersJSONFile, err)
        }

        json.Unmarshal(proxyRequestHeadersJSON, &proxyRequestHeaders)
        for _, header := range proxyRequestHeaders {
            if header.Name == "" {
                log.Fatalf("Proxy request headers JSON file: %q contains an element without a Name", proxyRequestHeadersJSONFile)
            }
        }
    }

    http.Handle("/", VerifyToken(MainHandler()))

    if tlsCert != "" && tlsKey != "" {
        http.ListenAndServeTLS(listenAddress + ":" + listenPort, tlsCert, tlsKey, handlers.LoggingHandler(os.Stdout, http.DefaultServeMux))
    } else {
        http.ListenAndServe(listenAddress + ":" + listenPort, handlers.LoggingHandler(os.Stdout, http.DefaultServeMux))
    }
}
