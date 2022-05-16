# Test My Signature

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A guide of the Test My Signature demo application.

---

## About

The "Test my Signature" application is buildt on top of the [Test my eID](https://github.com/swedenconnect/test-my-eid)
application. This app has been constructed in order to demonstrate how to put together a SAML SP that communicates
with the Identity Providers in the Sweden Connect-federation. The "Test my Signature" application is an overlay 
of this app, and adds integration against a Signature Service so that a user may sign a document after he, or she, 
has logged in against an IdP in Sweden Connect.

Using the SignService Integration API can be done in two ways:

- Using the Java API and setting up the necessary beans direct in your application, or, 
- Communicating with stand-alone REST-service that exposes methods for creating signature requests and 
  processing sign responses.
  
The "Test my Signature" demonstrates how to use both options. The drawback of using the Java API directly in
your application is that a rather complex configuration needs to be provided. The obvious advantage is that
you don't have to have another service running.

## Configuration of Test my Signature

As mentioned, the "Test my Signature" application, is an overlay of the 
[Test my eID](https://github.com/swedenconnect/test-my-eid) app, and many config settings regarding 
SAML authentication are set in this app. This section will focus on the configuration settings for the 
SignService Integration API.


### Configuring for using the REST SignService Integration

To configure the "Test my Signature" to use a stand-alone integration service is simple and only 
requires the following settings:

```
1. signservice.rest.enabled=true
2. signservice.rest.server-url=https://sig.idsec.se/signint
3. signservice.rest.client-username=testmyeid
4. signservice.rest.client-password=secret
```

1. By setting `signservice.rest.enabled` to `true` we tell the app that it should use the REST-connection
   and not use the Java API directly.
   
2. The URL to the SignService Integration REST-service.

3. The username for our application. In our demo app, every REST-call is authenticated using Basic authn
   and this setting tells which username to use.
   
4. The password for authenticating the REST-calls.

### Configuring for using the SignService Integration Java API

To use the SignService Integration Java API we need to supply more settings. The class 
[JavaApiSignServiceIntegrationConfiguration](https://github.com/idsec-solutions/signservice-integration/blob/master/test-my-signature/src/main/java/se/idsec/signservice/integration/app/config/JavaApiSignServiceIntegrationConfiguration.java)
sets up the following beans:

- [SignRequestProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/process/SignRequestProcessor.java) - A bean that is used to create a SignRequest message. A [DefaultSignRequestProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/process/impl/DefaultSignRequestProcessor.java)
bean will be set up having the following properties/sub-beans:

  - A list of to-be-signed document processors ([TbsDocumentProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/document/TbsDocumentProcessor.java)). These beans are used to calculate the hash of a document (or "calculate to-be-signed").
  One bean for each supported document type is added (XML and PDF).
  
  - A [SignMessageProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/signmessage/SignMessageProcessor.java) bean that is responsible of
  creating, and potentially encrypt, the "sign message". This message is included in the SignRequest and forwarded
  to the Identity Provider when the user "authenticates for signature". This setting is only relevant for 
  federations that support the SignMessage extension (i.e. Sweden Connect). 

- [SignResponseProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/process/SignResponseProcessor.java) - A bean that is used to process
a received SignResponse message and to compile a completed document including the signature. A [DefaultSignResponseProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/process/impl/DefaultSignResponseProcessor.java) bean is
set up having the following properties/sub-beans:

  - [SignResponseProcessingConfig](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/process/SignResponseProcessingConfig.java) - A configuration
  bean holding the configuration for how to process the response.
  
  - A list of [SignedDocumentProcessor](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/document/SignedDocumentProcessor.java) beans.
  These beans are used to process the signature and to create a signed document. A bean for each supported
  document type is supplied (XML, PDF).
  
- [IntegrationServiceConfiguration](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/config/IntegrationServiceConfiguration.java) - The configuration
  for the integration service. This bean contains the application (i.e. Sign Requester) credentials (a JKS
  or PKCS#12 file) that is used to sign SignRequest messages and a set of default settings as defined in
  [IntegrationServiceDefaultConfiguration](https://github.com/idsec-solutions/signservice-integration-api/blob/master/src/main/java/se/idsec/signservice/integration/config/IntegrationServiceDefaultConfiguration.java). These
  settings are described below.


Our integration software needs to be supplied with a set of default values for a number of parameters that are 
always the same, for example, the application's signature credentials (every call must be digitally signed), 
addresses and also SAML to certificate attribute mappings.

A SignService Integration instance may be configured with one, or more, *policies*, that sets the above. Usually
one policy is sufficient. 

So, let's configure our app to use the SignService Integration Java API ...

First, obviously, we need to make sure that the REST-connection is disabled:

```
signservice.rest.enabled=false
```

Next, we start defining our (only) policy. In our example it is called `sandbox`, since we are running 
against the Sweden Connect Sandbox-federation. It is possible to assign a default policy name. 

```
signservice.default-policy-name=sandbox
```

By setting a default policy, you don't have to give the policy name in every call to the integration API.

The [IntegrationServiceDefaultConfiguration](https://github.com/idsec-solutions/signservice-integration-api/blob/master/src/main/java/se/idsec/signservice/integration/config/IntegrationServiceDefaultConfiguration.java) interface 
describes all settings for a SignService Integration Policy. Below follows the settings used in the
"Test my Signature" application (with some values changed for clarity).

```
1. signservice.config.policy=sandbox

2. signservice.config.default-sign-requester-id=https://demo.example.com/sign
3. signservice.config.default-return-url=https://demo.example.com/process-response


4. signservice.config.default-signature-algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256

5. signservice.config.sign-service-id=https://sig.sandbox.swedenconnect.se/sigservice/test
6. signservice.config.default-destination-url=https://sig.sandbox.swedenconnect.se/sigservice/request
7. signservice.config.sign-service-certificates[0]=classpath:refsignservice-sign.crt

8. signservice.config.trust-anchors[0]=classpath:refsignservice-ca-root.crt
```

1. The name of the policy that we are declaring.

2. The SignRequester ID. This is the ID for the Sign Requester, i.e., our application. This name
must be known by, and registered at the SignService.

3. The default return URL. A policy may register a "default return URL" which is the URL to which 
the SignService will post the user back to after a signature operation has been completed. Our application
must be ready to accept POST requests on this URL. If no URL is given, this data must be supplied in
each call to [SignServiceIntegrationService.createSignRequest](https://github.com/idsec-solutions/signservice-integration-api/blob/master/src/main/java/se/idsec/signservice/integration/SignServiceIntegrationService.java)
(see below).

4. The default signature algorithm to include in signature requests. An application seldom wants to
alternate between different algorithms, so setting this default value keeps the integration code smaller.

5. The SignService ID. The unique ID of the SignService that we are sending our requests to.

6. The default URL at the SignService for sending requests. Typically, one application uses the same 
SignService URL for all its requests so this default should be set.

7. A list of one or more certificates. This certificate, or these certificates, are used by the SignService
to sign its response messages, and the SignService Integration API needs to use this/these to verify
the signature on response messages.

8. The SignService uses a CA (Certificate Authority) to create and issue certificates. These certificates
are issued under a "root". In order for our SignService Integration software to be able to verify
the issued certificates, the CA root (or roots) must be configured. This information is provided by 
the SignService.

OK, let's proceed to a tricky part. The application that is requesting a signature by directing its
user to the SignService needs to provider information about how user identity attributes are mapped
and added to the signature certificate that is issued by the SignService. The application can choose
to supply this information in each call to the SignService Integration API, but since these settings
probably will be the same for all users it is wise to set up a default "certificate requirements"
structure.

```
signservice.config.default-certificate-requirements.certificateType=PKC

signservice.config.default-certificate-requirements.attribute-mappings[0].sources[0].name=urn:oid:1.2.752.29.4.13
signservice.config.default-certificate-requirements.attribute-mappings[0].sources[1].name=urn:oid:1.2.752.201.3.4
signservice.config.default-certificate-requirements.attribute-mappings[0].destination.type=rdn
signservice.config.default-certificate-requirements.attribute-mappings[0].destination.name=2.5.4.5
signservice.config.default-certificate-requirements.attribute-mappings[0].destination.friendly-name=serialNumber
signservice.config.default-certificate-requirements.attribute-mappings[0].destination.required=true

...

signservice.config.default-certificate-requirements.attribute-mappings[4].sources[0].name=urn:oid:2.5.4.6
signservice.config.default-certificate-requirements.attribute-mappings[4].destination.type=rdn
signservice.config.default-certificate-requirements.attribute-mappings[4].destination.name=2.5.4.6
signservice.config.default-certificate-requirements.attribute-mappings[4].destination.friendly-name=C
signservice.config.default-certificate-requirements.attribute-mappings[4].destination.required=false
signservice.config.default-certificate-requirements.attribute-mappings[4].destination.default-value=SE
```

So, what does the above mean? First, the `certificateType` specifies `PKC` which is an ordinary public
key certificate. But the rest?

Next follows a list of "attribute mapping". Each mapping specifies one or more "sources" and a "destination".

So what the first listing means is:

> When the SignService authenticates the user for signature it should use either the `urn:oid:1.2.752.29.4.13`
(Swedish personal identity number) or the `urn:oid:1.2.752.201.3.4` (provisional ID from an eIDAS authentication)
and place that in an RDN (relative distinguished name) of the certificate having the name `2.5.4.5` (the serial number
attribute). The `required` field indicates that at least one of the source attributes must be received from
the authentication phase.

The last example is similar to the first with the difference:

> The `required` field is set to `false` meaning that the `urn:oid:2.5.4.6` (country) attribute is not
required. But. Since a `default-value` is supplied it tells the SignService to use this value and place in
the country RDN of the certificate should the source attribute not be present.

#### PDF Signature Images and Sign Pages

> TBD

## Creating a SignRequest

The `sendSignRequest` method in the [SignController](https://github.com/idsec-solutions/signservice-integration/blob/master/test-my-signature/src/main/java/se/idsec/signservice/integration/app/controller/SignController.java) 
class illustrates how a SignRequest message is created using the SignService Integration API. The user
has previously logged in, and the method gets information about the currently logged in user from the
session. 

> Note: The example code also contains code for preparing the PDF document for including a signature page/image. We
will add some notes about this later on ...

## Processing a SignResponse

The `processSignResponse` method in the [SignController](https://github.com/idsec-solutions/signservice-integration/blob/master/test-my-signature/src/main/java/se/idsec/signservice/integration/app/controller/SignController.java) class
illustrates how our application processes a SignResponse message being received.

---

Copyright &copy; 2019-2022, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).




