---
## Queue-Fair Go / Golang Adapter README & Installation Guide

Queue-Fair can be added to any web server easily in minutes.  You will need a Queue-Fair account - please visit https://queue-fair.com/sign-up if you don't already have one.  You can get a Free Tier account now for free.  You should also have received our Technical Guide.

## Client-Side JavaScript Adapter

Most of our customers prefer to use the Client-Side JavaScript Adapter, which is suitable for all sites that wish solely to protect against overload.

To add the Queue-Fair Client-Side JavaScript Adapter to your web server, you don't need the Go files included in this extension.

Instead, add the following tag to the `<head>` section of your pages:
 
```
<script data-queue-fair-client="CLIENT_NAME" src="https://files.queue-fair.net/queue-fair-adapter.js"></script>`
```

Replace CLIENT_NAME with the account system name visibile on the Account -> Your Account page of the Queue-Fair Portal

You shoud now see the Adapter tag when you perform View Source after refreshing your pages.

And you're done!  Your queues and activation rules can now be configured in the Queue-Fair Portal.

## Server-Side Adapter

The Server-Side Adapter when run in Safe mode means that your web server communicates directly with the Queue-Fair servers, rather than your visitors' browsers.

This can introduce a dependency between our systems, which is why most customers prefer the Client-Side Adapter.  See Section 10 of the Technical Guide for help regarding which integration method is most suitable for you.

The Server-Side Adapter is a small Go library that will run when visitors access your site.  It periodically checks to see if you have changed your Queue-Fair settings in the Portal, but other than that if the visitor is requesting a page that does not match any queue's Activation Rules, it does nothing.

If a visitor requests a page that DOES match any queue's Activation Rules, the Adapter consults the Queue-Fair Queue Servers to make a determination whether that particular visitor should be queued (Safe mode) or sends the visitor to the Queue-Fair Queue Servers to be counted and queued if necessary (Simple mode).  If the visitor is sent to our Queue Servers execution and generation of the page for that HTTP request for that visitor will cease.  If the Adapter determines that the visitor should not be queued, it sets a cookie to indicate that the visitor has been processed and your page executes and shows as normal.

Thus the Server-Side Adapter prevents visitors from skipping the queue by disabling the Client-Side JavaScript Adapter, and also reduces load on your web server when things get busy.

This distribution includes a simple Go server using the net/http framework in the httpserver folder, and the Adapter code in the queuefair folder.

The Adapter supports multiple Go HTTP frameworks.  The default queue_fair_http_service.go uses net/http and is suitable for plain Go web servers and also the Chi framework.  Additional framework implementations for Gin, Fiber and Echo are available in the services subfolder - if you are using one of these, copy the service for the framework you need into the parent queuefair folder, and change the service instantiation line `queuefair.NewQueueFairHTTPService` in main.go to use it.

If you are not using Chi, Echo, Fiber, Gin or plain net/http, but some other framework, instantiate queue_fair_service.go for your framework - it's only four basic functions to write.

Here's step by step instructions.

**1.** Copy the queuefair folder from this distribution into the top level folder of your go server.  If you are building the sample httpserver from this distro, copy it into the httpserver folder. 

**2.** **IMPORTANT:** Make sure the system clock on your webserver is accurately set to network time! On unix systems, this is usually done with the ntp package.  It doesn't matter which timezone you are using.  For Debian/Ubuntu:

```
    sudo apt-get install ntp
```

**3.** In your Go server you will need the `checkQueueFair()` function from main.go.  edit it to use your Account secret and system name from the Portal (or you can edit queue_fair_config.go with these values).  These are both on the Account -> Your Account page - don't use any queue secret or system name from any Queue Settings tab.  Call `checkQueueFair()` in the manner indicated in the main.go example file from within your Go server code at the *start* of processing of any *page* request.  

**4.** Note the `QueueFairConfig.SettingsCacheLifetimeMinutes` setting - this is how often your web server will check for updated settings from the Queue-Fair queue servers (which change when you hit Make Live).   The default value is 5 minutes.  You can set this to 0 to download a fresh copy with every request but **DON'T DO THIS** on your production machine/live queue with real people, or your server may collapse under load.  Between requests, these settings are stored in memory.

**5.** Note the `QueueFairConfig.AdapterMode` setting.  "safe" is recommended - we also support "simple" - see the Technical Guide for further details.

**6.** **IMPORTANT** Note the `QueueFairConfig.Debug` setting - this is set to true in the example code but you MUST set debug to false on production machines/live queues as otherwise your web logs will rapidly become full.  You can safely set it to a single IP address to just output debug information for a single visitor, even on a production machine.  Debug logging messages are routed through the Go log framework, but you can change that by editing queue_fair_logger.go

Once that's done you can run the included sample httpserver by cd'ing into that folder and running

```
    go run main.go
```

That's it your done!

In your go web server page functions you should always ensure that `checkQueueFair()` is the *first* thing that happens within your functions.  This will ensure that the Adapter is the first thing that runs when a vistor accesses any page, which is necessary both to protect your server from load from lots of visitors and also so that the adapter can set the necessary cookies.  You can then use the Activation Rules in the Portal to set which pages on your site may trigger a queue.  

  In the case where the Adapter sends the request elsewhere (for example to show the user a queue page), `checkQueueFair()` will return false and the rest of the page should not be run - see the `allPaths()` function in main.go for an example.

If it returns true, you MUST use the same ResponseWriter object (or Context, Ctx for other frameworks) that you passed to checkQueueFair() for the rest of your function, as otherwise people's Passed Cookies will not be set and they will be sent to the queue repeatedly.

** IMPORTANT ** You would normally exclude asset requests from the Adapter - it is normally just run on whole page requests, not images, static css files etc.  You should make sure any WebHook callbacks (e.g. from Payment Gateways) are *always* excluded from the Adapter. 

** IMPORTANT ** If your web server is sitting behind a proxy, CDN or load balancer, you may need to edit the property sets in `checkQueueFair()` to use values from forwarded headers instead for the protocol and client remote IP address.  The sample code in `checkQueueFair()` will check industry-standard X-Forwarded-For and X-Forwarded-Proto, but some providers don't conform to the standard and you may need to change the header names.  If you need help with this, contact Queue-Fair support.

If you are using the Hybrid Security Model and do not need to run the full Adapter process, just validate a Passed Cookie on your order page, the code for that is in `checkQueueFair()` too - it's the commmented-out stanza as indicated.

### To test the Server-Side Adapter

Use a queue that is not in use on other pages, or create a new queue for testing.

#### Testing SafeGuard
Set up an Activtion Rule to match the page you wish to test.  Hit Make Live.  Go to the Settings page for the queue.  Put it in SafeGuard mode.  Hit Make Live again.

In a new Private Browsing window, visit the page on your site.  

 - Verify that you can see debug output from the Adapter in your error-log.
 - Verify that a cookie has been created named `Queue-Fair-Pass-queuename`, where queuename is the System Name of your queue
 - If the Adapter is in Safe mode, also verify that a cookie has been created named QueueFair-Store-accountname, where accountname is the System Name of your account (on the Your Account page on the portal).
 - If the Adapter is in Simple mode, the Queue-Fair-Store cookie is not created.
 - Hit Refresh.  Verify that the cookie(s) have not changed their values.

#### Testing Queue
Go back to the Portal and put the queue in Demo mode on the Queue Settings page.  Hit Make Live.  Close ALL Private Browsing windows and open a new one (to clear out all cookies).  In the new Private Browsing window visit a protected URL.

 - Verify that you are now sent to queue.
 - When you come back to the page from the queue, verify that a new QueueFair-Pass-queuename cookie has been created.
 - If the Adapter is in Safe mode, also verify that the QueueFair-Store cookie has not changed its value.
 - Hit Refresh.  Verify that you are not queued again.  Verify that the cookies have not changed their values.

**IMPORTANT:**  Once you are sure the Server-Side Adapter is working as expected, remove the Client-Side JavaScript Adapter tag from your pages, and don't forget to disable debug level logging by setting `QueueFairConfig.Debug` to false (its default value), and also set `QueueFairConfig.SettingsCacheLifetimeMinutes` to at least 5 (also its default value).

**IMPORTANT:**  Responses that contain a Location header or a Set-Cookie header from the Adapter must not be cached!  You can check which cache-control headers are present using your browser's Inspector Network Tab.  The Adapter will add a Cache-Control header to disable caching if it sets a cookie or sends a redirect - but you must not override these with your own code or framework.

### For maximum security

The Server-Side Adapter contains multiple checks to prevent visitors bypassing the queue, either by tampering with set cookie values or query strings, or by sharing this information with each other.  When a tamper is detected, the visitor is treated as a new visitor, and will be sent to the back of the queue if people are queuing.

 - The Server-Side Adapter checks that Passed Cookies and Passed Strings presented by web browsers have been signed by our Queue-Server.  It uses the Secret visible on each queue's Settings page to do this.
 - If you change the queue Secret, this will invalidate everyone's cookies and also cause anyone in the queue to lose their place, so modify with care!
 - The Server-Side Adapter also checks that Passed Strings coming from our Queue Server to your web server were produced within the last 300 seconds, which is why your clock must be accurately set.
 -  The Server-Side Adapter also checks that passed cookies were produced within the time limit set by Passed Lifetime on the queue Settings page, to prevent visitors trying to cheat by tampering with cookie expiration times or sharing cookie values.  So, the Passed Lifetime should be set to long enough for your visitors to complete their transaction, plus an allowance for those visitors that are slow, but no longer.
 - The signature also includes the visitor's User-Agent, to further prevent visitors from sharing cookie values.

## AND FINALLY

All client-modifiable settings are in the `queue_fair_config.go` class.  You should never find you need to modify `queue_fair_adapter.go` - but if something comes up, please contact support@queue-fair.com right away so we can discuss your requirements.

Remember we are here to help you! The integration process shouldn't take you more than an hour - so if you are scratching your head, ask us.  Many answers are contained in the Technical Guide too.  We're always happy to help!
