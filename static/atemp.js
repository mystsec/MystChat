const messagesDiv = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
var loadingMsg = document.getElementById('loading-message'); //select loading message
const loadingPopup = document.getElementById('loading-popup');
const connectPopup = document.getElementById('connection-popup');
var popup = document.getElementById('init-popup');
var cid = '';
var current_cid = '';
var auth = '';
var uuid = '';
var id = '';
var invite_key = '';
var current_key = '';
var aes_key = '';
const csrftoken = getCookie('csrftoken');
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);

document.getElementById('hnm').onclick = function() {
  window.open('/');
}

window.onload = async function(){
  const csrftoken1 = document.getElementsByName('csrfmiddlewaretoken')[0].value;
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
  else
  {
    document.documentElement.setAttribute('data-theme', 'dark');//'light');
  }

  document.getElementById('init-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    popup.style.display = 'none';
    loadingPopup.classList.remove('hidden');
    await fetch('/api/join-temp/?id='+urlParams.get('id'))
      .then(response => response.json())
      .then(async data => {
        if (data[0] != 'auth-fail')
        {
          cid = data[0];
          current_cid = cid;
          auth = data[1];
          id = data[2];
        }
        else
        {
          loadingMsg.innerHTML = "Failed to Authenticate!<br>Each join link can only be used once. If you have already joined using this link, create a new chat.";
        }
      });

    await generate_AES_KEY(urlParams.get('sd'), urlParams.get('st')).then(async (vals) => {
      aes_key = vals;

      await fetch('../api/get/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/text', 'X-CSRFToken': csrftoken1},
        body: JSON.stringify({ 'cid': cid, 'auth': auth })
      })
      .then(response => response.json())
      .then(async data => {
        if (data[0] != 'auth-fail')
        {
          current_key = data[0];
          let iv = data[1];

          await AES_DECRYPT(aes_key, current_key, iv).then((plain) => {

            current_key = plain;
            getMessages(cid);
            getMsgStream(cid);
	    startCountdown();
            setTimeout(purge, 1000 * 60 * 60 * 24);

          });
        }
      });
    });
  });
}

window.onbeforeunload = function() {
  return "If You Leave, You Won't Be Able To Access This Chat Anymore!";
};



// handles send message click
messageForm.addEventListener('submit', async (event) => {

  // prevent the form from submitting and reloading the page
  event.preventDefault();

  document.getElementById('send').setAttribute('disabled', 'disabled');

  // get the value of the message input field
  const message = messageInput.value;

  if(!isEmptyOrSpaces(message)){
  await sendMessage(message, current_cid);
  }
  else
  {
    document.getElementById('send').removeAttribute('disabled');
  }
  messageInput.value = '';

});

function isEmptyOrSpaces(str){
    return str === null || str.match(/^ *$/) !== null;
}

// encrypts and sends a message to the server
async function sendMessage(message, cid) {

  await AES_ENCRYPT(current_key, message).then(async (ciph) => {
            // Use fetch() to send an HTTP POST request to the server
            await fetch('../api/send/', {
              method: 'POST',
              headers: { 'Content-Type': 'application/text', 'X-CSRFToken': csrftoken},
              body: JSON.stringify({ 'message': ciph[0], 'usr': uuid.innerText, 'iv': ciph[1], 'cid': cid, 'auth': auth})
            })
              .then(response => {

		document.getElementById('send').removeAttribute('disabled');
                if (response.ok) {
                  // If the message was sent successfully, log a success message
                  console.log('Message sent!');
                } else {
                  // If there was an error sending the message, log an error message
                  console.error('Error sending message');
                }
              })
              .catch(error => {
		document.getElementById('send').removeAttribute('disabled');
                // If there was an error with the fetch() call, log the error
                console.error(error);
              });

              setTimeout(scroll, 500);

    });



}


// retrieve previous messages from the server
async function getMessages(cid) {

  // Use fetch() to send an HTTP GET request to the server
  await fetch('/api/messages/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/text', 'X-CSRFToken': getCookie('csrftoken')},
    body: JSON.stringify({'cid': cid, 'auth': auth})
  })
    .then(response => response.json())
    .then(async data => {
      if(data[0] == 'user-mismatch')
      {
        console.log('User Mismatch Error');
      }
      setTimeout(show, 100);

      // Clear the messages div
      messagesDiv.innerHTML = '';

      // Loop through the array of messages
      data.forEach(async message => {

        // Create a new div element for the message
        const messageDiv = document.createElement('div');
        messageDiv.style.width = '40vw';
        const td = document.createElement('div');
        const blank = document.createElement('br');
        const spacing = document.createElement('div');

        let usr = message[0]['usr'];

        spacing.style.float = "right";
        spacing.style.textAlign = "right";
        spacing.style.clear = "right";

        if (usr == uuid.innerText)
        {
          messageDiv.style.float = 'right';
          messageDiv.style.textAlign = 'right';
          messageDiv.style.clear = "right";
          td.style.float = 'right';
          td.style.textAlign = 'right';
          td.style.clear = "right";
          blank.style.float = 'right';
          blank.style.textAlign = 'right';
        }
        else {
          messageDiv.style.float = 'left';
          messageDiv.style.textAlign = 'left';
          messageDiv.style.clear = "left";
          td.style.float = 'left';
          td.style.textAlign = 'left';
          td.style.clear = "left";
          blank.style.float = 'left';
          blank.style.textAlign = 'left';
        }

        // Set the message text as the content of the div

        await AES_DECRYPT(current_key, message[0]['message'], message[0]['iv']).then((plain) => {
          messageDiv.innerHTML = plain + '\n\n' + "<br><small><small>Sent at   " + message[1].substr(0,8) + " UTC   on   " + message[2] + '</small></small><br><br>\n\n\n\n';
        });


        // Add the message div to the messages div
        if (usr == uuid.innerText)
        {
          messagesDiv.appendChild(messageDiv);
          messagesDiv.appendChild(blank);

        }
        else {
          messagesDiv.appendChild(spacing);
          messagesDiv.appendChild(messageDiv);
          messagesDiv.appendChild(td);
          messagesDiv.appendChild(blank);
        }


        // Scroll to the bottom of the messages div
        console.log('Retrieved Old Messages!');
        scroll();
      });


    })
    .catch(error => {
      // If there was an error with the fetch() call, log the error
      console.error(error);
    });

}

document.getElementById('reconnect').addEventListener('click', async (event) => {
          connectPopup.classList.add('hidden');
          loadingMsg.innerText = 'Reconnecting ...';
          loadingPopup.classList.remove('hidden');
          getMessages(cid);
          getMsgStream(cid);
        });

// retrieves new messages near real time as they are sent to server
async function getMsgStream(cid) {
  console.log('CONNECTING');
  console.log(id);
  var source = new EventSource('../stream/?id='+id);
  current_chat_stream = source;
  //let status = 'failure';
  source.onopen = function(e) {
    return 'success';
  };

  source.onerror = function(err) {
        current_chat_stream.close();
        let status = 'failure';
        messagesDiv.setAttribute('hidden', 'none');
        connectPopup.classList.remove('hidden');
	/*document.getElementById('reconnect').addEventListener('click', async (event) => {
          connectPopup.classList.add('hidden');
          loadingMsg.innerText = 'Reconnecting ...';
          loadingPopup.classList.remove('hidden');
          getMessages(cid);
          getMsgStream(cid);
        });*/
        return status;
  };

  source.onmessage = function(event) {
    if(event.data == "['auth-fail']")
    {
      console.log('Authentication Failure');
    }
    else if(event.data[0] == "['user-mismatch']")
    {
      console.log('User Mismatch Error');
    }
    else if (event.data == 'pass')
    {
      console.log('Pass');
    }
    else if (event.data.substring(0,5) == "['ID:")
    {
      //console.log(event.data);
      id = event.data.substring(14, event.data.length - 3);
      console.log(id);
    }
    else {
      data = event.data;
      response = new Response(data);
      response.json().then(async (data) => {

        message = data;

	if (message[0]['message'] == 'JOINED')
        {
          console.log('Pass');
        }
        else if (message[0]['message'] == 'PURGED')
        {
          messagesDiv.innerHTML = '';
          cid = '';
          current_cid = '';
          auth = '';
          uuid = '';
          invite_key = '';
          current_key = '';
          aes_key = '';
          document.getElementById('cd').setAttribute('hidden', 'none');
          loadingMsg.innerText = 'The chat was ended by the host, all data was successfully deleted!';
          connectPopup.classList.add('hidden');
          loadingPopup.classList.remove('hidden');
          current_chat_stream.close();
          window.onbeforeunload = null;
        }
        else
        {

        // Create a new div element for the message
        const messageDiv = document.createElement('div');
        messageDiv.style.width = '40vw';
        const td = document.createElement('div');
        const blank = document.createElement('br');
        const spacing = document.createElement('div');

        let usr = message[0]['usr'];

        let msg = message[0]['message']

        spacing.style.float = "right";
        spacing.style.textAlign = "right";
        spacing.style.clear = "right";

        if (usr == uuid.innerText)
        {
          messageDiv.style.float = 'right';
          messageDiv.style.textAlign = 'right';
          messageDiv.style.clear = "right";
          td.style.float = 'right';
          td.style.textAlign = 'right';
          td.style.clear = "right";
          blank.style.float = 'right';
          blank.style.textAlign = 'right';
        }
        else {
          messageDiv.style.float = 'left';
          messageDiv.style.textAlign = 'left';
          messageDiv.style.clear = "left";
          td.style.float = 'left';
          td.style.textAlign = 'left';
          td.style.clear = "left";
          blank.style.float = 'left';
          blank.style.textAlign = 'left';
        }

        await AES_DECRYPT(current_key, msg, message[0]['iv']).then((plain) => {
          messageDiv.innerHTML = plain + '\n\n' + "<br><small><small>Sent at   " + message[1].substr(0,8) + " UTC   on   " + message[2] + '</small></small><br><br>\n\n\n\n';
        });

        // Add the message div to the messages div
        if (usr == uuid.innerText)
        {

          messagesDiv.appendChild(messageDiv);
          messagesDiv.appendChild(blank);

        }
        else {
          messagesDiv.appendChild(spacing);
          messagesDiv.appendChild(messageDiv);
          messagesDiv.appendChild(td);
          messagesDiv.appendChild(blank);
        }
        console.log('Received New Message!');
        scroll();
	}
      });
    }


  };
}





/*
Convert  an ArrayBuffer into a string
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

/*
 Convert a string into an ArrayBuffer
 from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
 */
 function str2ab(str) {
   const buf = new ArrayBuffer(str.length);
   const bufView = new Uint8Array(buf);
   for (let i = 0, strLen = str.length; i < strLen; i++) {
     bufView[i] = str.charCodeAt(i);
   }
   return buf;
 }

function td2int(arr) {
  t = arr[1];
  d = arr[2];
  let tarr = t.split(':');
  let darr = d.split('-');
  let tint = parseInt(tarr[0]) * 3600 + parseInt(tarr[1]) * 60 + parseInt(tarr[2]);
  let dint = (parseInt(darr[0]) - 2020) * 365 + parseInt(darr[1]) * 30 + parseInt(darr[2]);
  return [dint, tint];
}

async function insertionSort(arr){
    //Start from the second element.
    for(let i = 1; i < arr.length;i++){

        //Go through the elements behind it.
        for(let j = i - 1; j > -1; j--){

            //value comparison using ascending order.
            if(td2int(arr[j + 1])[0] < td2int(arr[j])[0]){

                //swap
                [arr[j+1],arr[j]] = [arr[j],arr[j + 1]];

            } else if(td2int(arr[j + 1])[0] == td2int(arr[j])[0])
            {
              if (td2int(arr[j + 1])[1] < td2int(arr[j])[1])
              {
                [arr[j+1],arr[j]] = [arr[j],arr[j + 1]];
              }
            }
        }
    };

  return arr;
}

function show() {
  messagesDiv.removeAttribute('hidden');
  loadingPopup.classList.add('hidden');
}

function scroll() {
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function isNumeric(str) {
  if (typeof str != "string") return false // we only process strings!
  return !isNaN(str) && // use type coercion to parse the _entirety_ of the string (`parseFloat` alone does not do this)...
         !isNaN(parseFloat(str)) // ...and ensure strings of whitespace fail
}

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function purge() {
  messagesDiv.innerHTML = '';
  cid = '';
  current_cid = '';
  auth = '';
  uuid = '';
  invite_key = '';
  current_key = '';
  aes_key = '';
  document.getElementById('cd').setAttribute('hidden', 'none');
  loadingMsg.innerText = 'Chat successfully self destructed after 24hrs. All data has been deleted for your security.';
  connectPopup.classList.add('hidden');
  loadingPopup.classList.remove('hidden');
  current_chat_stream.close();
  window.onbeforeunload = null;
}

function startCountdown() {
  // Set the date we're counting down to
  const date = new Date();
  date.setHours(date.getHours() + 24)
  var countDownDate = date.getTime();

  // Update the count down every 1 second
  var x = setInterval(function() {

    // Get today's date and time
    var now = new Date().getTime();

    // Find the distance between now and the count down date
    var distance = countDownDate - now;

    // Time calculations for, hours, minutes and seconds
    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);

    document.getElementById("cdt").innerHTML = "Self Destructs In: " + hours + "h "
    + minutes + "m " + seconds + "s ";

    // If the count down is finished, write some text
    if (distance < 0) {
      clearInterval(x);
      document.getElementById("cdt").innerHTML = "Self Destructing ...";
    }
  }, 1000);
}

async function AES_ENCRYPT(key, plaintext)
{
  return new Promise((resolve, reject) => {
    let iv = window.crypto.getRandomValues(new Uint8Array(128));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(key)),
      'AES-GCM',
      false,
      ["encrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.encrypt(
          {name: 'AES-GCM',
           iv: iv
          },
          key,
          str2ab(plaintext)
        ).then((ciphertext) => {
              iv = btoa(ab2str(iv));
              resolve([btoa(ab2str(ciphertext)), iv]);
            });
        });
  });
}


async function AES_DECRYPT(key, ciphertext, iv)
{
  return new Promise((resolve, reject) => {
    iv = str2ab(atob(iv));
    window.crypto.subtle.importKey(
      "raw",
      str2ab(atob(key)),
      'AES-GCM',
      false,
      ["decrypt"]
    ).then(async (key) => {
        await window.crypto.subtle.decrypt(
          {name: 'AES-GCM',
           iv: iv
          },
          key,
          str2ab(atob(ciphertext))
        ).then((plaintext) => {
            resolve(ab2str(plaintext));
        });
    });
  });
}


async function generate_AES_KEY()
{
  const seed = window.crypto.getRandomValues(new Uint8Array(64));
  const salt = window.crypto.getRandomValues(new Uint8Array(64));
  const iterations = 1000000;

  return new Promise(async (resolve, reject) => {
  await window.crypto.subtle.importKey(
    'raw',
    seed,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  ).then(async (derivedKey) => {

      await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-512',
        },
        derivedKey,
        {
          name: 'AES-GCM',
          length: 256,
        },
        true,
        ["encrypt", "decrypt"]
      ).then(async (keyMaterial) => {
        await window.crypto.subtle.exportKey(
          "raw",
          keyMaterial
        ).then(function(exportedSecretKey) {
          const exportedAsString = ab2str(exportedSecretKey);
          const exportedAsBase64 = window.btoa(exportedAsString);
          resolve(exportedAsBase64);

        });
      });
    });
  });
}


async function generate_AES_KEY(sd, st)
{
  const seed = str2ab(atob(b64url_to_b64(sd)));
  const salt = str2ab(atob(b64url_to_b64(st)));
  const iterations = 1000000;

  return new Promise(async (resolve, reject) => {
  await window.crypto.subtle.importKey(
    'raw',
    seed,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  ).then(async (derivedKey) => {

      await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-512',
        },
        derivedKey,
        {
          name: 'AES-GCM',
          length: 256,
        },
        true,
        ["encrypt", "decrypt"]
      ).then(async (keyMaterial) => {
        await window.crypto.subtle.exportKey(
          "raw",
          keyMaterial
        ).then(function(exportedSecretKey) {
          const exportedAsString = ab2str(exportedSecretKey);
          const exportedAsBase64 = window.btoa(exportedAsString);
          resolve(exportedAsBase64);

        });
      });
    });
  });
}


function encode_utf8(s) {
  return unescape(encodeURIComponent(s));
}


function decode_utf8(s) {
  return decodeURIComponent(escape(s));
}

function base64decode(str) {
  let decode = atob(str).replace(/[\x80-\uffff]/g, (m) => `%${m.charCodeAt(0).toString(16).padStart(2, '0')}`)
  return decodeURIComponent(decode)
}

function decodeBase64(s) {
    var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
    var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(i=0;i<64;i++){e[A.charAt(i)]=i;}
    for(x=0;x<L;x++){
        c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
        while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
    }
    return r;
}

function b64_to_b64url(s) {
  return s.replace(/\+/g, '-').replace(/\//g, '_');
}

function b64url_to_b64(s) {
  return s.replace(/-/g, '+').replace(/_/g, '/');
}



function toggleDarkMode()
{
  const current = document.documentElement.getAttribute('data-theme');
  if (current == 'terminal')
  {
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.setItem('theme', 'light');
  }
  else {
    document.documentElement.setAttribute('data-theme', 'terminal');
    localStorage.setItem('theme', 'terminal');
  }
}
