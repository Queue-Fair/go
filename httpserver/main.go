package main

import (
	"httpserver/queuefair"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"net/http"
	"os"
)

func checkQueueFair(w http.ResponseWriter, r *http.Request) (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Queue-Fair Exception:", err)
			//If an exception occurs during Queue-Fair processing, show the page.
			ok = true;
		}
	}()

	// Configure Queue-Fair

	// From the Account -> Your Account page in the Portal (not any Queue Settings tab)
	queuefair.QueueFairConfig.Account = "DELETE_AND_REPLACE_WITH_YOUR_ACCOUNT_SECRET"

	// From the Account -> Your Account page in the Portal (not any Queue Settings tab)
	queuefair.QueueFairConfig.AccountSecret = "DELETE_AND_REPLACE_WITH_YOUR_ACCOUNT_SYSTEM_NAME"

	// Set to false for production systems.
	queuefair.QueueFairConfig.Debug = false

	// Extract required fields

	// Will check for X-Forwarded-Proto, and if not found, get from the request.
	// If your server is behind a reverse proxy (load balancer etc) that uses
	// a different header name for the BROWSER's protocol, change it here.
	isSecure := false
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		isSecure = proto == "https"
	} else {
		isSecure = r.TLS != nil
	}

	// Will check for X-Forwarded-For, and if not found, get from the request.
	// If your server is behind a reverse proxy (load balancer etc) that uses
	// a different header name for the BROWSER's protocol (such as Cloudflare),
	// change it here.
	remoteIP := r.Header.Get("X-Forwarded-For")
	if remoteIP == "" {
		//Split this as r.RemoteAddr is "clientIP:port"
		var err error
		remoteIP, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// fallback if something goes wrong
			remoteIP = r.RemoteAddr
		}
	} else {
		//Split this as X-Forwarded-For may be "clientIP, otherIP, otherIP..."
		parts := strings.Split(remoteIP, ",")
		remoteIP = strings.TrimSpace(parts[0])
	}

	//Construct the full URL.
	protocol := "http"
	if isSecure {
		protocol = "https"
	}

	requestedURL := r.URL.String()
	if r.URL.RawQuery != "" {
		requestedURL = r.URL.Path + "?" + r.URL.RawQuery
	}
	requestedURL = fmt.Sprintf("%s://%s%s", protocol, r.Host, requestedURL)

	//Get the browser User Agent
	userAgent := r.Header.Get("User-Agent")

	//Make the Service and Adapter objects for this request
	service := queuefair.NewQueueFairHTTPService(w, r, isSecure);
	adapter := queuefair.NewQueueFairAdapter(service, requestedURL, userAgent, remoteIP, "")

	// Uncomment below to only validate the cookie manually on a particular URL /app/
	/*
		if strings.Contains(requestedURL, "/app/") {
			queueName := "YOUR_QUEUE_NAME"
			secret := "YOUR_QUEUE_SECRET"
			lifetimeMinutes := 60
			cookie := service.GetCookie(queuefair.CookieNameBase + queueName)
			if !adapter.ValidateCookie(secret, lifetimeMinutes, cookie) {
				redirectURL := fmt.Sprintf("https://%s.queue-fair.net/%s?qfError=InvalidCookie",
					queuefair.QueueFairConfig.Account, queueName)
				adapter.Redirect(redirectURL, 0)
				return false
			}
			return true
		}
	*/

	// Full Adapter evaluation
	if !adapter.IsContinue() {
		return false
	}

	return true
}

func allPaths(w http.ResponseWriter, r *http.Request) {
	if(!checkQueueFair(w,r)) {
		//Queue-Fair says deny.
		return
	}
	io.WriteString(w, "This is my website!\n")
}

func doNothing(w http.ResponseWriter, r *http.Request) {
}

func main() {
	fmt.Printf("Starting web server at http://localhost:3333\n");
	http.HandleFunc("/", allPaths)
	http.HandleFunc("/favicon.ico", doNothing)
	err := http.ListenAndServe(":3333", nil)
    if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
