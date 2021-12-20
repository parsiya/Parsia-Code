# Proof of Concept for VS Code Remote WSL Remote Code Execution - CVE-2021-43891
See the blog at
https://parsiya.net/blog/2021-12-20-rce-in-visual-studio-codes-remote-wsl-for-fun-and-negative-profit.

Also https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43891.

## Building

1. `npm install`.
2. Store `vsda.node` for your architecture in `/routes/vsda.node`.
3. Run `npm start` or use `ctrl+shift+b` in VS Code.
4. Open `http://localhost:3000` and follow the instructions.

### Where is vsda.node?

* Windows: `C:\Program Files\Microsoft VS Code\resources\app\node_modules.asar.unpacked\vsda\build\Release\vsda.node`.
* Server (WSL): `~/.vscode-server/bin/{commit}/node_modules/vsda/build/Release/vsda.node`.

### Using the Node Inspector Instance and Popping Calc
This probably only works locally because we need to connect directly to the
Inspector instance.

1. Edit `/public/javascripts/nem.js` and search for `ZZZ`.
2. Uncomment the next two lines (see below).

```js
// in nem.js - uncomment the two lines after ZZZ`
// ZZZ
// const res = await (await postJSON('/inspect', packet.data)).arrayBuffer();
// showMessage(bufferToString(res));
```

1. Edit `/routes/sign.js` and search for `ZZZ`.
2. Modify the IP address in `popCalc`.

```js
// ZZZ Change the IP address here.
popCalc('192.168.1.130', port);
```

## LICENSE
MIT, see [LICENSE](LICENSE).