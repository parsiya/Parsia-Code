# Random Code <!-- omit in toc -->
This repository contains most of the code that I write for my blog posts. I
realized I have random repositories on Github. I am consolidating them into one.

# Individual Licenses <!-- omit in toc -->
Most code in this repository is governed under the [MIT](LICENSE-code). Some
code may have a different license, check each directory for a license file.

# Security Code <!-- omit in toc -->
Security code will be mostly in
[https://github.com/parsiya/Go-Security](https://github.com/parsiya/Go-Security).

# Code Index <!-- omit in toc -->
This table will help but may not be current. Look inside each individual
directory to see the code.

- [WinAppDbg Tutorials](#winappdbg-tutorials)
- [Proof of Concepts](#proof-of-concepts)
    - [Code WSL Remote RCE - CVE-2021-4389](#code-wsl-remote-rce---cve-2021-4389)
- [Semgrep](#semgrep)
    - [Semgrep Autofix](#semgrep-autofix)
- [Go](#go)
    - [Cryptopals](#cryptopals)
    - [Gophercises](#gophercises)
    - [Blackfriday and gographviz](#blackfriday-and-gographviz)
    - [Byte Wrangling and Windows Filetime](#byte-wrangling-and-windows-filetime)
    - [filePath.Ext notes](#filepathext-notes)
    - [SANS Holiday Hack Challenge 2018](#sans-holiday-hack-challenge-2018)
- [Python](#python)
    - [Hipchat Proxy](#hipchat-proxy)
    - [Malware Adventure](#malware-adventure)
    - [Customizing SimpleHTTPServer](#customizing-simplehttpserver)
    - [pcap2csv](#pcap2csv)
- [.NET Remoting](#net-remoting)
- [Burp](#burp)
    - [Cryptography in Python Burp Extensions](#cryptography-in-python-burp-extensions)
    - [Hiding OPTIONS in Burp](#hiding-options-in-burp)
    - [Swing in Python Burp Extensions](#swing-in-python-burp-extensions)
    - [Using Mozilla Rhino to Run JavaScript in Java](#using-mozilla-rhino-to-run-javascript-in-java)
    - [Java SQLite Test](#java-sqlite-test)
- [Cryptography](#cryptography)
    - [Cryptopals in C](#cryptopals-in-c)
    - [Decrypting an Application's Encrypted Log](#decrypting-an-applications-encrypted-log)
- [Endpoint Discovery using Windows DNS Cache](#endpoint-discovery-using-windows-dns-cache)
- [Octopress Image Popup Plugin Forked](#octopress-image-popup-plugin-forked)
- [Calculator in C++](#calculator-in-c)

## [WinAppDbg Tutorials](winappdbg-tutorials)
Code for my set of WinAppDbg tutorials.

1. Copy the `winappdbg` directory to your Virtual Machine.
2. Install Python, WinAppDbg and other software using instructions in part 1.
3. Follow the tutorials and enjoy.
4. If code is wrong, make an issue here or yell at me on Twitter/email/etc.

- [Part 1 - Basics][winappdbg-1]
- [Part 2 - Function Hooking and Others][winappdbg-2]
- [Part 3 - Manipulating Function Calls][winappdbg-3]
- [Part 4 - Bruteforcing FlareOn 2017 - Challenge 3][winappdbg-4]

## Proof of Concepts

### [Code WSL Remote RCE - CVE-2021-4389](code-wsl-rce/README.md)
See the blog at
[https://parsiya.net/blog/2021-12-20-rce-in-visual-studio-codes-remote-wsl-for-fun-and-negative-profit].arrayBuffer

Also exists in [https://github.com/parsiya/code-wsl-rce][code-wsl-gh].

[code-wsl-blog]: https://parsiya.net/blog/2021-12-20-rce-in-visual-studio-codes-remote-wsl-for-fun-and-negative-profit
[code-wsl-gh]: https://github.com/parsiya/code-wsl-rce

## Semgrep

### [Semgrep Autofix](semgrep-autofix)
Practice rules and code for the blog
[A Hands-On Intro to Semgrep's Autofix][semgrep-autofix-blog].

## Go
Go is dope, also see https://github.com/parsiya/Go-Security.

### [Cryptopals](cryptopals/go)
Doing the Cryptopals challenges with `lol no generics`.

### [Gophercises](gophercises/)
[Gophercises](https://gophercises.com/) by Jon Calhoun.

### [Blackfriday and gographviz](markdown-parsing)
Code for blog post [Blackfriday's Parser and Generating graphs with gographviz][blackfriday-gographviz].

### [Byte Wrangling and Windows Filetime](filetime-bytewrangling/)
Code for blog post [Windows Filetime Timestamps and Byte Wrangling with Go][byte-wrangling].

### [filePath.Ext notes](filepath-ext)
Code for blog post [filepath.Ext Notes][filepath-ext].

### [SANS Holiday Hack Challenge 2018](sans-holidayhack-2018)
See the write-up at:

* https://parsiya.net/blog/2019-01-15-sans-holiday-hack-challenge-2018-solutions/

Files:

* `decrypt.go`: Decrypts the password vault.
* `cleaned-malware.ps1`: Cleaned version of the PowerShell malware.

## Python

### [Hipchat Proxy](hipchat-proxy)
Small proxy that I wrote for proxying Hipchat.

- Main blog post
    - [Proxying Hipchat Part 3: SSL Added and Removed Here][hipchat-3]
- Related blogs:
    - [Proxying Hipchat Part 1: Where did the Traffic Go?][hipchat-1]
    - [Proxying Hipchat Part 2: So You Think You Can Use Burp?][hipchat-2]

### [Malware Adventure](malware-adventure)
Small text adventure written in Python using PAWS (Python Adventure Writing
System). Created as part of the class activity for "Advanced Topics in Computer
Security" in 2013 at Johns Hopkins.

PAWS 2.1 is a fork by `Matthias C. Hormann` at
[https://github.com/Moonbase59/PAWS][paws-github]. PAWS was originally created
by `Roger Plowman`.

- Blog post
    - [Malware Adventure][malware-adventure-blog]
- Github repository (because there are links to it)
    - [https://github.com/parsiya/malwareadventure][malware-adventure-github]

### [Customizing SimpleHTTPServer](python-simplehttpserver)
Code for the blog post
[Customizing Python's SimpleHTTPServer][python-httpserver].

### [pcap2csv](pcap2csv)
A few python scripts to extract information from pcap files to csv.

## [.NET Remoting](net-remoting)
Code and example program used in:

- [Intro to .NET Remoting for Hackers][net-remoting]

## Burp
Mostly Burp extension code.

### [Cryptography in Python Burp Extensions](python-burp-crypto)
Code and example program used in:

- [Cryptography in Python Burp Extensions][python-burp-crypto-blog]

### [Hiding OPTIONS in Burp](burp-filter-options)
Code used in:

- [Hiding OPTIONS - An Adventure in Dealing with Burp Proxy in an Extension][burp-filter-options-blog]

### Swing in Python Burp Extensions

* Part 1 blog: Swing in Python Burp Extensions - Part 1
    * https://parsiya.net/blog/2019-11-04-swing-in-python-burp-extensions-part-1/
    * [Part 1 code](jython-swing-1)
* Part 2 blog:
    * Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels
    * https://parsiya.net/blog/2019-11-11-swing-in-python-burp-extensions-part-2-netbeans-and-tablemodels/
    * [Part 2 code](jython-swing-2)

### [Using Mozilla Rhino to Run JavaScript in Java](java-rhino)
Code used in:

- [Using Mozilla Rhino to Run JavaScript in Java][java-rhino]

### [Java SQLite Test](java-sqlite-test)
Sample code to learn how to interact with a SQLite database in Java with
`org.xerial.sqlite-jdbc`.

## Cryptography

### [Cryptopals in C](cryptopals/c)
Doing the first few cryptopals challenges in C (why?!).

### [Decrypting an Application's Encrypted Log](decrypt-log)
This code decrypts an application's logs. It uses the Mersenne Twister Engine
with a specific seed to create a key stream. See the blog post at:

* [The Encrypted Logz - Some Simple Reverse Engineering][encrypted-logz].

## [Endpoint Discovery using Windows DNS Cache](dns-cache)
A couple of PowerShell scripts that use the Windows DNS cache to discover application endpoints.

- Blog post: [Thick Client Proxying - Part 9 - The Windows DNS Cache][dns-cache]

## [Octopress Image Popup Plugin Forked](https://github.com/parsiya/octopress-image-popup-forked)
This is a fork of the Octopress Image Popup Plugin at
[https://github.com/ctdk/octopress-image-popup][original-popup] by Jeremy
Bingham. The original instructions did not work for me out of the box so I made
some minor changes. Because it has a different license, I am keeping it in a
separate repository.

- Blog post
    - [Image Popup and Octopress][pop-up-blog].

## [Calculator in C++](calculator.cpp)
I found this code in an old archive. It's some calculator I wrote back in
undergrad. It draws shapes on the screen and depending on where you click, you
get a number. Pretty much all of it was done manually. The only thing I
remember, is that I needed to have `C:\\egavga.bgi` for it to work. Fun times.

<!-- Links -->

[hipchat-1]: https://parsiya.net/blog/2015-10-08-proxying-hipchat-part-1-where-did-the-traffic-go/
[hipchat-2]: https://parsiya.net/blog/2015-10-09-proxying-hipchat-part-2-so-you-think-you-can-use-burp/
[hipchat-3]: https://parsiya.net/blog/2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here/
[net-remoting]: https://parsiya.net/blog/2015-11-14-intro-to-.net-remoting-for-hackers/
[original-popup]: https://github.com/ctdk/octopress-image-popup
[pop-up-blog]: https://parsiya.net/blog/2015-07-26-image-popup-and-octopress/
[pop-up-github]: https://github.com/parsiya/octopress-image-popup-forked
[paws-github]: https://github.com/Moonbase59/PAWS
[malware-adventure-blog]: https://parsiya.net/blog/2014-09-21-malware-adventure/
[malware-adventure-github]: https://github.com/parsiya/malwareadventure
[winappdbg-1]: https://parsiya.net/blog/2017-11-09-winappdbg---part-1---basics/
[winappdbg-2]: https://parsiya.net/blog/2017-11-11-winappdbg---part-2---function-hooking-and-others/
[winappdbg-3]: https://parsiya.net/blog/2017-11-15-winappdbg---part-3---manipulating-function-calls/
[winappdbg-4]: https://parsiya.net/blog/2017-11-15-winappdbg---part-4---bruteforcing-flareon-2017---challenge-3/
[go-pcap]: https://parsiya.net/blog/2017-12-03-go-and-pcaps/
[blackfriday-gographviz]: https://parsiya.net/blog/2018-10-28-blackfridays-parser-and-generating-graphs-with-gographviz/
[byte-wrangling]: https://parsiya.net/blog/2018-11-01-windows-filetime-timestamps-and-byte-wrangling-with-go/
[filepath-ext]: https://parsiya.net/blog/2018-11-10-filepath.ext-notes/
[python-burp-crypto-blog]: https://parsiya.net/blog/2018-12-23-cryptography-in-python-burp-extensions/
[burp-filter-options-blog]: https://parsiya.net/blog/2019-04-06-hiding-options-an-adventure-in-dealing-with-burp-proxy-in-an-extension/
[dns-cache]: https://parsiya.net/blog/2019-04-28-thick-client-proxying-part-9-the-windows-dns-cache/
[java-rhino]: https://parsiya.net/blog/2019-12-22-using-mozilla-rhino-to-run-javascript-in-java/
[encrypted-logz]: https:///parsiya.net/blog/2020-04-17-the-encrypted-logz-some-simple-reverse-engineering/
[python-httpserver]: https://parsiya.net/blog/2020-11-15-customizing-pythons-simplehttpserver/
[semgrep-autofix-blog]: https://parsiya.net/blog/2021-10-23-a-hands-on-intro-to-semgreps-autofix/