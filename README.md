# WNFuck
Windows Notification Facility (WNF) is an interesting undocumented Windows kernel component aimed to provide a pub-sub notification system. During my talk "What The (WNF)uck?!" at Spanish h-c0n 2023 conference I showed different POCs I developed to demonstrate:
* Basic server-client interaction
* Process Injection ([as modexp shows here](https://modexp.wordpress.com/2019/06/15/4083/))
* Data persistence (in kernel)
* Other interesting WNF tricks

In this repo you will find the POCs I developed. Don't expect nothing fancy, it's not a tool or anything, just POC C# code. If you are looking for something more ellaborated, check [Alex Ionescu's wnfun](https://github.com/ionescu007/wnfun) or [daem0nc0re's C# port of Ionescu's tool](https://github.com/daem0nc0re/SharpWnfSuite).
