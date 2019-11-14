![Logo](img/idsec.png)

# SignService Integration Service API

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Open Source Signature Service Integration API

---

> Introtext ...

## Policies

A SignService Integration Service runs under one, or more policies. A policy tells how the SignService Integration is configured regarding the signature requester attributes and requirements, as well as security parameters such as signing certificates. The API exposes `IntegrationServiceDefaultConfiguration` which is an interface that defines the default settings for a given policy.

## Creating a SignRequest

### /v1/create - Create a SignRequest

Minimal example (using default settings from configuration):

```
{
  "signRequesterID" : "https://qa.test.swedenconnect.se/sp",
  "authnRequirements" : {
    "authnServiceID" : "https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com",
    "authnContextRef" : "http://id.elegnamnden.se/loa/1.0/loa3",
    "requestedSignerAttributes" : [ {
      "name" : "urn:oid:1.2.752.29.4.13",
      "value" : "196911292032"
    } ]
  },
  "tbsDocuments" : [ {
    "id" : "doc-1",
    "content" : "PE15RG9jPjxWYWx1ZT5BcHByb3ZlPC9WYWx1ZT48L015RG9jPg==",
    "mimeType" : "application/xml"
  } ],
  "signMessageParameters" : {
    "signMessage" : "I approve this contract",
    "performEncryption" : true,
    "mimeType" : "TEXT",
    "mustShow" : true,
    "displayEntity" : "https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com"
  }
}
```

Complete example where every parameter is assigned (not relying on defaults):

```
{
  "correlationId" : "d59278ec-da00-448a-a04a-1dc102319053",
  "policy" : "swedish-eid",
  "signRequesterID" : "https://qa.test.swedenconnect.se/sp",
  "returnUrl" : "https://qa.test.swedenconnect.se/signresponse",
  "destinationUrl" : "https://sign.idsec.se/request",
  "signatureAlgorithm" : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "authnRequirements" : {
    "authnServiceID" : "https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com",
    "authnContextRef" : "http://id.elegnamnden.se/loa/1.0/loa3",
    "requestedSignerAttributes" : [ {
      "type" : "saml",
      "name" : "urn:oid:1.2.752.29.4.13",
      "value" : "196911292032",
      "nameFormat" : "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
      "attributeValueType" : "string"
    }, {
      "name" : "urn:oid:1.3.6.1.5.5.7.9.1",
      "value" : "1969-11-29"
    } ]
  },
  "certRequirements" : {
    "certificateType" : "PKC",
    "attributeMappings" : [ {
      "sources" : [ {
        "type" : "saml",
        "name" : "urn:oid:1.2.752.29.4.13"
      } ],
      "destination" : {
        "type" : "rdn",
        "name" : "2.5.4.5",
        "friendlyName" : "serialNumber",
        "required" : true
      }
    }, {
      "sources" : [ {
        "name" : "urn:oid:2.5.4.6"
      } ],
      "destination" : {
        "type" : "rdn",
        "name" : "urn:oid:2.5.4.6",
        "defaultValue" : "SE",
        "friendlyName" : "country",
        "required" : true
      }
    } ]
  },
  "tbsDocuments" : [ {
    "id" : "doc-1",
    "content" : "PE15RG9jPjxWYWx1ZT5BcHByb3ZlPC9WYWx1ZT48L015RG9jPg==",
    "mimeType" : "application/xml",
    "processingRules" : "rule-xyz",
    "adesRequirement" : {
      "adesFormat" : "EPES",
      "signaturePolicy" : "etsi123"
    }
  } ],
  "signMessageParameters" : {
    "signMessage" : "I approve this contract",
    "performEncryption" : true,
    "mimeType" : "TEXT",
    "mustShow" : true,
    "displayEntity" : "https://idp-sweden-connect-valfr-2017-ct.test.frejaeid.com"
  }
}
```

---Copyright &copy; 2019, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).