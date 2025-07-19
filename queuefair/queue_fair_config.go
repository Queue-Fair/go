package queuefair

// QueueFairConfig holds adapter settings.
type Config struct {
	AccountSecret                   string
	Account                         string
	FilesServer                     string
	QueryTimeLimitSeconds           int
	Debug                           interface{}
	ReadTimeout                     int
	SettingsCacheLifetimeMinutes int
	StripPassedString               bool
	AdapterMode                     string
}

// QueueFairConfig is the global config instance.
var QueueFairConfig = Config {
	// Your Account Secret is shown on the Your Account page of
    // the Queue-Fair Portal.If you change it there, you must
    // change it here too.
	AccountSecret:                   "DELETE_AND_REPLACE_WITH_YOUR_ACCOUNT_SECRET",

	// The System Name of your account from the Your Account page
	// of the Queue-Fair Portal.
	Account:                         "DELETE_AND_REPLACE_WITH_YOUR_ACCOUNT_SYSTEM_NAME",

	// Leave this set as is
	FilesServer:                     "files.queue-fair.net",

	// Time limit for Passed Strings to be considered valid,
    // before and after the current time
	QueryTimeLimitSeconds:           300,

	// Valid values are true, false, or an "IP_address".
	Debug:                           false,

	// How long to wait in seconds for network reads of config
	// or Adapter Server (safe mode only)
	ReadTimeout:                     5,

	// How long a cached copy of your Queue-Fair settings will be kept in
	// memory before downloading a fresh copy. Set this to 0 if you are updating your settings in
    // the Queue-Fair Portal and want to test your changes quickly, but remember
    // to set it back to at least 5 again when you are finished.  The settings file
    // has a CDN timeout of 5 minutes anyway, so setting this to less than 5 is of little value.
	SettingsCacheLifetimeMinutes: 	 5,

	// Whether or not to strip the Passed String from the URL
	// that the Visitor sees on return from the Queue or Adapter servers
	// (simple mode) - when set to true causes one additinal HTTP request
	// to CloudFlare but only on the first matching visit from a particular
	// visitor. The recommended value is true.
	StripPassedString:               true,

	// Whether to send the visitor to the Adapter server for counting (simple mode),
	// or consult the Adapter server (safe mode).The recommended value is "safe".
	// If you change this to "simple", consider setting stripPassedString above to
	// false to make it easier for Google to crawl your pages.
	AdapterMode:                     "safe",
}