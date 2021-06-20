# WebCryptographyAPI-Study

> :construction: Work in progress

Contains the materials used for the blog post about [Web Cryptography API](https://w3c.github.io/webcrypto/).

# Blog post link

XXX

# Study note

> :information_source: Download the PDF file to enable the links inside the PDF.

See file [study-note.pdf](study-note.pdf) to access to the full study note gathered and used for the blog post.

# Lab

## Public instance

The lab is automatically deployed via the [Github page feature](https://pages.github.com/) at each commit on the `main` branch on

https://excelliumsa.github.io/WebCryptographyAPI-Study/

## Local instance

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

2. Open the url `https://127.0.0.1:8443/docs` in your browser accept the certificate warning because **it is a self signed one**.
