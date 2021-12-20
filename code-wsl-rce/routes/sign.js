var express = require('express');
var router = express.Router();

const vsda = require('./vsda');
const signer = vsda.signer();

const buffer = require('buffer');
const { create } = require('domain');

/**
 * returns a protocol packet in an ArrayBuffer that we can send out as-is from
 * the browser.
 *
 * @param {number} packetType is a number between 1 and 6.
 * @param {number} packetID is the current message ID. Starts from 0.
 * @param {number} ackID is the message ID we are "ACKing."
 * @param {string} packetData is the contents of the packet.
 */
function createPacket(packetType, packetID, ackID, packetData) {
  // Fill the packet with 0x00.
  let buf = buffer.Buffer.alloc(1 + 12 + packetData.length).fill(0x00);

  // Set packet type. This should be a number between 1-6 (inclusive).
  buf[0] = packetType;

  // Write the packetID as big endian starting from offset 1.
  buf.writeUIntBE(packetID, 1, 4);

  // Write the ackID as big endian starting from offset 5.
  buf.writeUIntBE(ackID, 5, 4);

  // Write packetData's length as big endian starting from offset 9.
  buf.writeUIntBE(packetData.length, 9, 4);

  // Write the packet starting from offset 13.
  let bytesWritten = buf.write(packetData, 13);
  // console.log(`bytesWritte: ${bytesWritten}`);

  // console.log(buf.toString('hex'));
  return buf;
}

router.post('/', function(req, res, next) {
  // Sign whatever came in the POST request.
  // req.body is already parsed because we have the content-type.
  var signed = signer.sign(String(req.body.data));

  // Packet data.
  let packetData = `{"type":"connectionType","commit":"b3318bc0524af3d74034b8bb8a64df0ccf35549a","signedData":"${signed}","desiredConnectionType":2,"args":{"language":"en","break":false,"port":55000}}`;
  console.log(packetData);

  buf = createPacket(0x02, 0x00, 0x00, packetData);
  res.send(buf);
});

router.get('/', function(req, res, next) {
  res.send('Use POST with body parameter data.');
});


module.exports = router;
