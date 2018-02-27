
# PDFOnlineSignature

PDFOnlineSignatur is a cloud-enabled, mobile-ready, PDF signer developed on ASP.NET CORE.

### Current Features

  - Self-generated Certification Authority Certificate
  - Self-generated Web Server Certificate
  - Client Certificate based authentication ( Tested on Google Chrome and Mozilla Firefox )
  - Multiple Signatures
  - Online PDF Preview and Signer
  - Online Signature verification

### TODOs

  - Implement OCSP and CRL's
  - Drag and drop support

### INSTRUCTIONS

When the server runs for the first time it creates 3 certificates:

  - Certification Authority Root Certificate
  - Web Server Certificate
  - System Administrator Certificate
  
To be able to manage the platform users you need to install the System Administrator certificate, located on the CERT_ROOT directory, on a supported browser.

After you create the first user you can define another user as a system administrator.

### CERTIFICATION REQUEST

For a user to be able to sign a certificate request as to be done, the request will be set to the users email.
After following the instructions the user will recieve on ther email inbox his certificate ( P12 and CRT ), which 
he can uses to sign on a external software, or install the certificate on his browser to use the online platform.

For security reasons only operators can add/delete users and request their certificates, altought the request 
will be sent to the user email for he to finish the request.

### DEVELOPMENT

Want to contribute? Great! You are more than welcome.
This application was developed using Visual Studio Code and dotnet core on Ubuntu 16.04.

### Docker

A docker file is provided.



### Todos

 - Write MORE Tests
 - Add Night Mode

License
----

MIT

**Free Software, Hell Yeah!**