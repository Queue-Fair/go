package queuefair

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"fmt"
	"strconv"
	"strings"
	"time"
	"hash"
	"sync"
)

// PERSISTENT VARIABLES

// Client is reused, thread safe.
var client = &http.Client{
	Timeout: time.Duration(int(QueueFairConfig.ReadTimeout)) * time.Second,
}

// Settings are cached in memory between periodic downloads
var SharedSettingsCache *SettingsCache

// Hmac objects are pooled for maximum efficiency
var hmacPools sync.Map

////////////////////////////////////

/* Static-like functions */

func Urlencode(param string) string {
	return url.QueryEscape(param)
}

func Urldecode(param string) string {
	decoded, _ := url.QueryUnescape(param)
	return decoded
}


func optional(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return v.(string)
	}
	return ""
}


func ProcessIdentifier(parameter string) string {
	if parameter == "" {
		return ""
	}
	i := strings.Index(parameter, "[")
	if i == -1 || i < 20 {
		return parameter
	}
	return parameter[:i]
}

func isNumeric(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

func GetHash(secret, message string) string {

	/*
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	*/

	poolIface, _ := hmacPools.LoadOrStore(secret, &sync.Pool{
		New: func() interface{} {
			// Log("Creating hmac for "+secret);
			return hmac.New(sha256.New, []byte(secret))
		},
	})

	pool := poolIface.(*sync.Pool)
	mac := pool.Get().(hash.Hash)
	defer pool.Put(mac)

	mac.Reset()
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

////////////////////////////////////////

// Adapter starts here

type QueueFairAdapter struct {
	Service         QueueFairService
	RequestedURL    string
	UserAgent       string
	RemoteIP        string
	Extra           string
	ContinuePage    bool
	Parsing         bool
	Protocol        string
	Settings        map[string]interface{}
	AdapterResult   map[string]interface{}
	AdapterQueue    map[string]interface{}
	PassedString    string
	PassedQueues    map[string]bool
	UID             string
	D           bool
	AddedCacheCtrl  bool
}

func NewQueueFairAdapter(service QueueFairService, url, agent, ip, extra string) *QueueFairAdapter {
	return &QueueFairAdapter{
		Service:      service,
		RequestedURL: url,
		UserAgent:    agent,
		RemoteIP:     ip,
		Extra:        extra,
		ContinuePage: true,
		Protocol:     "https",
		PassedQueues: make(map[string]bool),
		D:        QueueFairConfig.Debug == true || QueueFairConfig.Debug == ip,
	}
}

func (a *QueueFairAdapter) SetUIDFromCookie() {
	cookieBase := "QueueFair-Store-" + QueueFairConfig.Account
	uidCookie := a.Service.GetCookie(cookieBase)
	if uidCookie == "" {
		return
	}

	i := strings.Index(uidCookie, "=")
	if i == -1 {
		i = strings.Index(uidCookie, ":")
	}
	if i == -1 {
		if a.D { a.log("separator not found in UID Cookie! " + uidCookie) }
		return
	}

	a.UID = uidCookie[i+1:]
	if a.D { a.log("UID set to " + a.UID) }
}

func (a *QueueFairAdapter) log(msg string) {
	if a.D { 		// Defined in queue_fair_logger.go - edit that file to use your preferred
		// logging framework.
		Log("QF " + msg)
	}
}

func (a *QueueFairAdapter) CheckAndAddCacheControl() {
	if !a.AddedCacheCtrl {
		a.Service.AddHeader("Cache-Control", "no-store, max-age=0")
		a.AddedCacheCtrl = true
	}
}

func processIdentifier(agent string) string {
	if i := strings.Index(agent, "["); i > 20 {
		return agent[:i]
	}
	return agent
}

func (a *QueueFairAdapter) ValidateQuery(queue map[string]interface{}) bool {
	parsedURL, err := url.Parse(a.RequestedURL)
	if err != nil {
		if a.D { a.log("Bad URL parse") }
		return false
	}
	q := parsedURL.Query()

	timestampStr := q.Get("qfts")
	if timestampStr == "" || !isNumeric(timestampStr) {
		if a.D { a.log("Invalid timestamp") }
		return false
	}
	timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)
	now := time.Now().Unix()

	if timestamp > now+int64(QueueFairConfig.QueryTimeLimitSeconds) || timestamp < now-int64(QueueFairConfig.QueryTimeLimitSeconds) {
		if a.D { a.log("Timestamp out of range") }
		return false
	}

	check := fmt.Sprintf("qfqid=%s&qfts=%s&qfa=%s&qfq=%s&qfpt=%s&",
		q.Get("qfqid"), q.Get("qfts"), q.Get("qfa"), q.Get("qfq"), q.Get("qfpt"))

	checkInput := processIdentifier(a.UserAgent) + check
	secret, _ := queue["secret"].(string)
	checkHash := GetHash(secret, checkInput)
	
	if checkHash != q.Get("qfh") {
		if a.D { a.log("Failed hash check") }
		return false
	}

	return true
}

func (a *QueueFairAdapter) parseLifetime(queue map[string]interface{}) int {
	lifetimeMinutesStr, _ := queue["passedLifetimeMinutes"].(string) // JSON numbers are float64
	lifetimeMinutes, err := strconv.Atoi(lifetimeMinutesStr)
	if err != nil {
		if a.D { a.log("Unparsable lifettimeMinutes "+lifetimeMinutesStr+" - using 20") }
    	lifetimeMinutes = 20
	}
	return lifetimeMinutes
}

func (a *QueueFairAdapter) ValidateCookieFromQueue(queue map[string]interface{}, cookie string) bool {
	return a.ValidateCookie(queue["secret"].(string), a.parseLifetime(queue), cookie)
}

func (a *QueueFairAdapter) ValidateCookie(secret string, passedLifetimeMinutes int, cookie string) bool {
	defer func() {
		if r := recover(); r != nil && a.D {
			a.log("Cookie Validation panic: " + fmt.Sprint(r))
		}
	}()

	if a.D { a.log("Validating cookie " + cookie) }

	values, err := url.ParseQuery(cookie)
	if err != nil {
		return false
	}

	mHash := values.Get("qfh")
	if mHash == "" {
		return false
	}

	hpos := strings.LastIndex(cookie, "qfh=")
	if hpos == -1 {
		return false
	}
	check := cookie[:hpos]

	checkInput := processIdentifier(a.UserAgent) + check
	checkHash := GetHash(secret, checkInput)

	if mHash != checkHash {
		if a.D { a.log("Cookie Hash Mismatch Given " + mHash + " Should be " + checkHash) }
		return false
	}

	tsStr := values.Get("qfts")
	tsInt, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	thresh := time.Now().Unix()-(int64(passedLifetimeMinutes)*60)

	if tsInt < thresh {
		if a.D { a.log(fmt.Sprintf("Cookie timestamp too old %.0f ", float64(time.Now().Unix())-float64(tsInt))) }
		return false
	}

	if a.D { a.log("Cookie Validated") }

	return true
}

func (a *QueueFairAdapter) CheckQueryString() {
	urlParams := a.RequestedURL

	if a.D { a.log("Checking URL for Passed String " + urlParams) }

	if !strings.Contains(urlParams, "qfqid=") {
		return
	}

	if a.D { a.log("Passed string found") }

	qfqPos := strings.Index(urlParams, "qfq=")
	if qfqPos == -1 {
		return
	}

	if a.D { a.log("Passed String with Queue Name found") }

	amp := strings.Index(urlParams[qfqPos:], "&")
	if amp == -1 {
		amp = len(urlParams)
	} else {
		amp += qfqPos
	}

	subStart := qfqPos + len("qfq=")
	queueName := urlParams[subStart:amp]

	if a.D { a.log("Queue name is " + queueName) }

	queues, ok := a.Settings["queues"].([]interface{})
	if !ok {
		if a.D { a.log("No queues array in settings") }
		return
	}

	for _, raw := range queues {
		queue, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := queue["name"].(string)
		if name != queueName {
			continue
		}

		if a.D { a.log("Found queue for querystring " + queueName) }

		value := urlParams
		start := strings.Index(value, "qfqid=")
		if start != -1 {
			value = value[start:]
		}

		if !a.ValidateQuery(queue) {
			cName := "QueueFair-Pass-" + queueName
			queueCookie := a.Service.GetCookie(cName)

			if queueCookie != "" {
				if a.D { a.log("Query validation failed but cookie " + queueCookie) }

				if a.ValidateCookieFromQueue(queue, queueCookie) {
					if a.D { a.log("The cookie is valid. That's fine") }
					return
				}

				if a.D { a.log("Query AND Cookie validation failed!!!") }
			} else {
				if a.D { a.log("Bad queueCookie for " + queueName + " " + queueCookie) }
			}

			if a.D { a.log("Query not valid. Redirecting to error page") }

			loc := a.Protocol + "://" + queue["queueServer"].(string) + "/" + queueName + "?qfError=InvalidQuery"
			a.Redirect(loc, 1)
			return
		}

		if a.D { a.log("Query validation succeeded for " + value) }

		a.PassedString = value

		cookieDomain := optional(queue, "cookieDomain")

		passedLifetime := a.parseLifetime(queue)

		a.SetCookie(queueName, value, passedLifetime*60, cookieDomain)

		if !a.ContinuePage {
			return
		}

		if a.D { a.log("Marking " + queueName + " as passed by queryString") }

		a.PassedQueues[queueName] = true
	}
}

func (a *QueueFairAdapter) GotSettings() {
	if a.D { a.log("Got client settings.") }

	a.CheckQueryString()
	if !a.ContinuePage {
		return
	}

	a.ParseSettings()
}

func (a *QueueFairAdapter) IsMatch(queue map[string]interface{}) bool {
	if queue == nil {
		return false
	}

	activation, ok := queue["activation"].(map[string]interface{})
	if !ok {
		return false
	}

	rules, ok := activation["rules"]
	if !ok {
		return false
	}

	return a.IsMatchArray(rules)
}

func (a *QueueFairAdapter) IsMatchArray(arr interface{}) bool {
	rules, ok := arr.([]interface{})
	if !ok || len(rules) == 0 {
		return false
	}

	firstOp := true
	state := false

	for i, rawRule := range rules {
		rule, ok := rawRule.(map[string]interface{})
		if !ok {
			continue
		}

		operator, _ := rule["operator"].(string)

		if !firstOp && operator != "" {
			if operator == "And" && !state {
				return false
			} else if operator == "Or" && state {
				return true
			}
		}

		ruleMatch := a.IsRuleMatch(rule)

		if firstOp {
			state = ruleMatch
			firstOp = false
			if a.D { a.log(fmt.Sprintf("  Rule 1: %v", ruleMatch)) }
		} else {
			if a.D { a.log(fmt.Sprintf("  Rule %d: %v", i+1, ruleMatch)) }
			switch operator {
			case "And":
				state = state && ruleMatch
				if !state {
					break
				}
			case "Or":
				state = state || ruleMatch
				if state {
					break
				}
			}
		}
	}

	if a.D { a.log(fmt.Sprintf("Final result is %v", state)) }
	return state
}

func (a *QueueFairAdapter) IsRuleMatch(rule map[string]interface{}) bool {
	comp := a.RequestedURL
	component, _ := rule["component"].(string)
	value, _ := rule["value"].(string)
	matchType, _ := rule["match"].(string)
	caseSensitive, _ := rule["caseSensitive"].(bool)
	negate, _ := rule["negate"].(bool)

	switch component {
	case "Domain":
		comp = strings.ReplaceAll(comp, "http://", "")
		comp = strings.ReplaceAll(comp, "https://", "")
		comp = strings.Split(comp, "?")[0]
		comp = strings.Split(comp, "#")[0]
		comp = strings.Split(comp, "/")[0]
		comp = strings.Split(comp, ":")[0]
	case "Path":
		strip := strings.ReplaceAll(comp, "http://", "")
		strip = strings.ReplaceAll(strip, "https://", "")
		strip = strings.Split(strip, "?")[0]
		strip = strings.Split(strip, "#")[0]
		strip = strings.Split(strip, "/")[0]
		strip = strings.Split(strip, ":")[0]

		idx := strings.Index(comp, strip)
		if idx != -1 {
			comp = comp[idx+len(strip):]
		}

		if strings.HasPrefix(comp, ":") {
			if i := strings.Index(comp, "/"); i != -1 {
				comp = comp[i:]
			} else {
				comp = ""
			}
		}

		if i := strings.Index(comp, "#"); i != -1 {
			comp = comp[:i]
		}
		if i := strings.Index(comp, "?"); i != -1 {
			comp = comp[:i]
		}
		if comp == "" {
			comp = "/"
		}
	case "Query":
		if strings.Contains(comp, "?") {
			comp = comp[strings.Index(comp, "?")+1:]
		} else {
			comp = ""
		}
	case "Cookie":
		name, _ := rule["name"].(string)
		comp = a.Service.GetCookie(name)
	}

	if !caseSensitive {
		comp = strings.ToLower(comp)
		value = strings.ToLower(value)
	}

	if a.D { a.log("  Testing " + component + " " + value + " against " + comp) }

	var ret bool

	switch matchType {
	case "Equal":
		ret = comp == value
	case "Contain":
		ret = comp != "" && strings.Contains(comp, value)
	case "Exist":
		ret = comp != ""
	}

	if negate {
		ret = !ret
	}

	return ret
}

func (a *QueueFairAdapter) IsPassed(queue map[string]interface{}) bool {
	name, _ := queue["name"].(string)
	if a.PassedQueues[name] {
		if a.D { a.log("Queue " + name + " marked as passed already.") }
		return true
	}

	cookieName := "QueueFair-Pass-" + name
	queueCookie := a.Service.GetCookie(cookieName)
	if queueCookie == "" {
		if a.D { a.log("No cookie found for queue " + name) }
		return false
	}

	if !strings.Contains(queueCookie, name) {
		if a.D { a.log("Cookie value is invalid for " + name) }
		return false
	}

	if !a.ValidateCookieFromQueue(queue, queueCookie) {
		if a.D { a.log("Cookie failed validation " + queueCookie) }
		cookieDomain := optional(queue, "cookieDomain")
		a.SetCookie(name, "", 0, cookieDomain)
		return false
	}

	if a.D { a.log("Found valid cookie for " + name) }
	return true
}

func (a *QueueFairAdapter) OnMatch(queue map[string]interface{}) bool {
	name, _ := queue["name"].(string)
	displayName, _ := queue["displayName"].(string)

	if a.IsPassed(queue) {
		if a.D { a.log("Already passed " + name + ".") }
		return true
	}

	if !a.ContinuePage {
		return false
	}

	if a.D { a.log("Checking at server " + displayName) }
	a.ConsultAdapter(queue)
	return false
}

func (a *QueueFairAdapter) SetCookie(queueName, value string, lifetimeSeconds int, cookieDomain string) {
	if a.D { a.log("Setting cookie for " + queueName + " to " + value) }

	cookieName := "QueueFair-Pass-" + queueName
	a.CheckAndAddCacheControl()
	a.Service.SetCookie(cookieName, value, lifetimeSeconds, cookieDomain)

	if lifetimeSeconds > 0 {
		a.PassedQueues[queueName] = true
		if QueueFairConfig.StripPassedString {
			loc := a.RequestedURL
			pos := strings.Index(loc, "qfqid=")
			if pos != -1 {
				if a.D { a.log("Stripping passedString from URL") }
				loc = loc[:pos-1]
				a.Redirect(loc, 0)
			}
		}
	}
}

func (a *QueueFairAdapter) Redirect(loc string, sleepSecs int) {
	if sleepSecs > 0 {
		time.Sleep(time.Duration(sleepSecs) * time.Second)
	}
	a.CheckAndAddCacheControl()
	a.Service.Redirect(loc)
	a.ContinuePage = false
}

func (a *QueueFairAdapter) ParseSettings() {
	if a.Settings == nil {
		if a.D { a.log("ERROR: Settings not set+") }
		return
	}

	rawQueues, ok := a.Settings["queues"].([]interface{})
	if !ok || len(rawQueues) == 0 {
		if a.D { a.log("No queues found+") }
		return
	}

	a.Parsing = true
	if a.D { a.log("Running through queue rules") }

	for _, raw := range rawQueues {
		queue, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := queue["name"].(string)
		displayName, _ := queue["displayName"].(string)

		if a.PassedQueues[name] {
			if a.D { a.log("Passed from array " + name) }
			continue
		}

		if a.D { a.log("Checking " + displayName) }

		if a.IsMatch(queue) {
			if a.D { a.log("Got a match " + displayName) }
			if !a.OnMatch(queue) {
				if !a.ContinuePage {
					return
				}
				if a.D { a.log("Found matching unpassed queue " + displayName) }
				if QueueFairConfig.AdapterMode == "simple" {
					return
				}
				continue
			}
			if !a.ContinuePage {
				return
			}
			a.PassedQueues[name] = true
		} else {
			if a.D { a.log("Rules did not match " + displayName) }
		}
	}

	if a.D { a.log("All queues checked") }
	a.Parsing = false
}

func (a *QueueFairAdapter) UrlToJSON(urlStr string) map[string]interface{} {

	resp, err := client.Get(urlStr)

	if err != nil {
		if a.D { a.log("Error fetching URL:" + urlStr + err.Error()) }
		return nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		if a.D { a.log("Error decoding JSON from " +urlStr+": " + err.Error()) }
		return nil
	}
	return result
}

func (a *QueueFairAdapter) ConsultAdapter(queue map[string]interface{}) {
	name := queue["name"].(string)
	if a.D { a.log("Consulting Adapter Server for queue " + name + " for page " + a.RequestedURL) }
	a.AdapterQueue = queue

	adapterMode := "safe"
	if val, ok := queue["adapterMode"].(string); ok {
		adapterMode = val
	} else if QueueFairConfig.AdapterMode != "" {
		adapterMode = QueueFairConfig.AdapterMode
	}

	if a.D { a.log("Adapter mode is " + adapterMode) }

	if adapterMode == "safe" {
		url := a.Protocol + "://" + queue["adapterServer"].(string) + "/adapter/" + name
		url += "?ipaddress=" + Urlencode(a.RemoteIP)

		if a.UID != "" {
			url += "&uid=" + a.UID
		}

		url += "&identifier=" + Urlencode(ProcessIdentifier(a.UserAgent))

		if a.D { a.log("Adapter URL " + url) }

		js := a.UrlToJSON(url)
		if js == nil {
			if a.D { a.log("No Adapter response") }
			return
		}
		if a.D { a.log("Got adapter response") }

		a.AdapterResult = js
		a.GotAdapter()
		if !a.ContinuePage {
			return
		}
	} else {
		url := a.Protocol + "://" + queue["queueServer"].(string) + "/" + name + "?target=" + Urlencode(a.RequestedURL)
		url = a.AppendVariant(queue, url)
		url = a.AppendExtra(queue, url)

		if a.D { a.log("Redirecting to adapter server " + url) }

		a.Redirect(url, 0)
	}
}

func (a *QueueFairAdapter) GotAdapter() {
	if a.D { a.log(fmt.Sprintf("Adapter response is %+v",a.AdapterResult)) }

	if a.AdapterResult == nil {
		if a.D { a.log("ERROR: GotAdapter() called without result") }
		return
	}

	uidVal, hasUID := a.AdapterResult["uid"].(string)
	if hasUID {
		if a.UID != "" && a.UID != uidVal {
			if a.D { a.log("UID Cookie Mismatch - expected " + a.UID + " but received " + uidVal) }
		} else {
			a.UID = uidVal
			cookieSeconds := int(a.AdapterResult["cookieSeconds"].(float64))
			domain := optional(a.AdapterQueue, "cookieDomain")
			a.Service.SetCookie("QueueFair-Store-"+QueueFairConfig.Account, "u:"+a.UID, cookieSeconds, domain)
		}
	}

	action, hasAction := a.AdapterResult["action"].(string)
	if !hasAction {
		if a.D { a.log("ERROR: GotAdapter() called without result action") }
		return
	}

	if action == "SendToQueue" {
		if a.D { a.log("Sending to queue server") }
		queryParams := "target=" + Urlencode(a.RequestedURL)

		if dynamicTarget, ok := a.AdapterQueue["dynamicTarget"].(string); ok && dynamicTarget == "path" {
			if i := strings.Index(a.RequestedURL, "?"); i != -1 {
				queryParams = "target=" + Urlencode(a.RequestedURL[:i])
			}
		}

		if a.UID != "" {
			queryParams += "&qfuid=" + a.UID
		}

		redirectLoc := a.AdapterResult["location"].(string)
		if queryParams != "" {
			redirectLoc += "?" + queryParams
		}

		redirectLoc = a.AppendVariant(a.AdapterQueue, redirectLoc)
		redirectLoc = a.AppendExtra(a.AdapterQueue, redirectLoc)

		if a.D { a.log("Redirecting to " + redirectLoc) }
		a.Redirect(redirectLoc, 0)
		return
	}

	// SafeGuard / Pass-through
	validation := Urldecode(a.AdapterResult["validation"].(string))
	cookieSecs := a.parseLifetime(a.AdapterQueue) * 60
	domain := optional(a.AdapterQueue, "cookieDomain")
	a.SetCookie(a.AdapterResult["queue"].(string), validation, cookieSecs, domain)

	if !a.ContinuePage {
		return
	}

	if a.D { a.log("Marking " + a.AdapterResult["queue"].(string) + " as passed by adapter")
	}

	a.PassedQueues[a.AdapterResult["queue"].(string)] = true
}


func (a *QueueFairAdapter) AppendVariant(queue map[string]interface{}, redirectLoc string) string {
	if a.D { a.log("Looking for variant") }

	variant := a.GetVariant(queue)
	if variant == "" {
		if a.D { a.log("No variant found") }
		return redirectLoc
	}

	if a.D { a.log("Found variant " + variant) }

	if strings.Contains(redirectLoc, "?") {
		redirectLoc += "&"
	} else {
		redirectLoc += "?"
	}

	redirectLoc += "qfv=" + Urlencode(variant)
	return redirectLoc
}

func (a *QueueFairAdapter) AppendExtra(queue map[string]interface{}, redirectLoc string) string {
	if a.Extra == "" {
		return redirectLoc
	}

	if a.D { a.log("Found extra " + a.Extra) }

	if strings.Contains(redirectLoc, "?") {
		redirectLoc += "&"
	} else {
		redirectLoc += "?"
	}

	redirectLoc += "qfx=" + Urlencode(a.Extra)
	return redirectLoc
}

func (a *QueueFairAdapter) GetVariant(queue map[string]interface{}) string {
	if a.D { a.log("Getting variants for " + queue["name"].(string)) }

	activation, ok := queue["activation"].(map[string]interface{})
	if !ok {
		return ""
	}

	variantRules, ok := activation["variantRules"].([]interface{})
	if !ok {
		return ""
	}

	if a.D { a.log("Checking variant rules for " + queue["name"].(string)) }

	for _, rawVariant := range variantRules {
		variant, ok := rawVariant.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := variant["variant"].(string)
		rules := variant["rules"]

		match := a.IsMatchArray(rules)
		if a.D { a.log(fmt.Sprintf("Variant match %s %v", name, match)) }
		if match {
			return name
		}
	}
	return ""
}

func (a *QueueFairAdapter) SettingsURL() string {
	return fmt.Sprintf("%s://%s/%s/%s/queue-fair-settings.json",
		a.Protocol,
		QueueFairConfig.FilesServer,
		QueueFairConfig.Account,
		QueueFairConfig.AccountSecret)
}

func (a *QueueFairAdapter) LoadSettings() {
	if strings.Contains(QueueFairConfig.Account, "DELETE") {
		panic("QF bad account name " + QueueFairConfig.Account + " - edit QueueFairConfig")
	}

	if SharedSettingsCache == nil {
		settingsURL := a.SettingsURL()
		SharedSettingsCache = NewSettingsCache(settingsURL, QueueFairConfig.SettingsCacheLifetimeMinutes)

		if a.D { a.log("Initialized SharedSettingsCache with URL: " + settingsURL)
		}
	}

	settings, err := SharedSettingsCache.Get(a)
	if err != nil {
		if a.D { a.log("Error retrieving settings: " + err.Error()) }
		a.Settings = nil
		return
	}

	a.Settings = settings
}

func (a *QueueFairAdapter) IsContinue() bool {
	if a.D { a.log("----Adapter Starting for " + a.RemoteIP) }

	a.SetUIDFromCookie()
	a.LoadSettings()
	if a.Settings == nil {
		return true
	}
	a.GotSettings()

	if a.D { a.log("----Adapter Ending for " + a.RemoteIP) }
	return a.ContinuePage
}
