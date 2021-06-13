# WebCryptographyAPI-Study

> :construction: Work in progress, see file [01-Web_Cryptography_API.pdf](01-Web_Cryptography_API.pdf) for status.

Contains the materials used for the blog post about Web Cryptography API.

# Blog post link

XXX

# Run the lab

1. Use the following set of command lines:

```shell
$ cd [REPO_CLONE_FOLDER]
$ # See https://www.npmjs.com/package/npx
$ # See https://www.npmjs.com/package/http-server
$ npx http-server -p 8443 -S -C cert.pem -K key.pem -c-1
Starting up http-server, serving ./ through https
Available on:
  ...
  https://127.0.0.1:8443
Hit CTRL-C to stop the server
```

Or use the launch configuration named `StartWebServerWithHTTPS` in the Visual Studio Code workspace provided. 

2. Open the url `https://127.0.0.1:8443` in your browser accept the certificate warning because **it is a self signed one**.

# Lab description

WIP.
