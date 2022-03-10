# Signature Service Integration Programming Guide

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Programming Guide for the Signature Service Integration Service.

---

## Table of contents

1. [**Introduction**](#introduction)

    1.1. [Getting the Artifacts](#getting_the_artifacts)

    1.2. [Java Documentation](#java_documentation)

    1.3. [Design Principles](#design_principles)

    1.3.1. [PostConstruct Annotations](#postconstruct_annotations)

    1.3.2. [Use of Lombok](#use_of_lombok)

    1.3.3. [Java Version Compatibility](#java_version_compatibility)

    1.3.4. [Logging](#logging)

2. [**Initializing the Library**](#initializing_the_library)

    2.1. [Spring Boot Example](#spring_boot_example_2)

    2.2. [Initializing Manually](#initializing_manually)

---

<a name="introduction"></a>
## 1. Introduction

This is the Programming Guide for how to use the implementation of the [Signature Service Intergration API](https://idsec-solutions.github.io/signservice-integration-api/). If you haven't already done so, check out the documentation for the API. There you find information about the federated signing concept and detailed descriptions of the actual API. This programming guide focuses on how to use the implementation of the API and assumes that you are familiar with the API.

<a name="getting_the_artifacts"></a>
### 1.1. Getting the Artifacts

The implementation of the Signature Service Integration API comprises of three artifacts:

- **signservice-integration-impl** - The core implementation of how to create a DSS `SignRequest` and how to process a DSS `SignResponse`.

- **signservice-integration-xml** - Support for signing XML documents.

- **signservice-integration-pdf** - Support for signing PDF documents.

Even though you can build the artifacts yourself by cloning the <https://github.com/idsec-solutions/signservice-integration> repo, it is probably easier to just download the artifacts from Maven central.

**signservice-integration-impl**

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-impl/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-impl)

```
<dependency>
  <groupId>se.idsec.signservice.integration</groupId>
  <artifactId>signservice-integration-impl</artifactId>
  <version>${signservice-impl.version}</version>
</dependency>
```

Note: The signservice-integration-impl artifact has an optional dependency to spring-core (`org.springframework:spring-core`). The only reason for that is if you need to use the `PdfSignatureImageTemplateExt` class. This will probably change in the future.

**signservice-integration-xml**

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-xml/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-xml)

If you want to support signing of XML documents, you need the **signservice-integration-xml** artifact.

```
<dependency>
  <groupId>se.idsec.signservice.integration</groupId>
  <artifactId>signservice-integration-xml</artifactId>
  <version>${signservice-xml.version}</version>
  <exclusions>
    <exclusion>
      <groupId>se.idsec.signservice.integration</groupId>
      <artifactId>signservice-integration-impl</artifactId>
    </exclusion>
  </exclusions>
</dependency>
```

Note: The exclusion of the implicit dependency to `signservice-integration-impl` and replacing it with an explicit dependency is a good practice, especially if an update of `signservice-integration-impl` is available.

**signservice-integration-pdf**

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-pdf/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.idsec.signservice.integration/signservice-integration-pdf)

If you want to support signing of PDF documents, you need the **signservice-integration-pdf** artifact.

```
<dependency>
  <groupId>se.idsec.signservice.integration</groupId>
  <artifactId>signservice-integration-pdf</artifactId>
  <version>${signservice-pdf.version}</version>
  <exclusions>
    <exclusion>
      <groupId>se.idsec.signservice.integration</groupId>
      <artifactId>signservice-integration-impl</artifactId>
    </exclusion>
  </exclusions>
</dependency>
```

Note: The exclusion of the implicit dependency to `signservice-integration-impl` and replacing it with an explicit dependency is a good practice, especially if an update of `signservice-integration-impl` is available.

<a name="java_documentation"></a>
### 1.2. Java Documentation

Java API documentation, or javadoc, for the API, implementations and the commons libraries are available here:

* [SignService Integration Service API](https://idsec-solutions.github.io/signservice-integration-api/javadoc/)

* [SignService Integration Service API Implementation](https://idsec-solutions.github.io/signservice-integration/javadoc/integration-impl/) (signservice-integration-impl)

* [SignService Integration Service - XML Support](https://idsec-solutions.github.io/signservice-integration/javadoc/xml/) (signservice-integration-xml)

* [Signer Service Integration Service - PDF Support](https://idsec-solutions.github.io/signservice-integration/javadoc/pdf/) (signservice-integration-xml)

* [SignService Commons](https://idsec-solutions.github.io/signservice-commons/javadoc/signservice-commons/) - A library containing utilities for JAXB and XML processing, certificate utilities and interfaces for signing and signature validation, see <https://github.com/idsec-solutions/signservice-commons>.

* [SignService XML Commons](https://idsec-solutions.github.io/signservice-commons/javadoc/xml-commons/) - Classes for XML signing and validation of XML signatures, see <https://github.com/idsec-solutions/signservice-commons>.

* [SignService PDF Commons](https://idsec-solutions.github.io/signservice-commons/javadoc/pdf-commons/) - Classes for PDF signing and validation of PDF signatures, see <https://github.com/idsec-solutions/signservice-commons>.

> *Note: We will put together a site where all the javadoc above is merged together.*

<a name="design_principles"></a>
### 1.3. Design Principles

The interfaces and classes of the SignService Integration libraries are built with dependency injection in mind, and most classes are constructed as beans with setter and getters for class properties.

Yes. We are Spring Framework fanatics, but you can use the libraries without Spring as well. However, there are a few things that you need to be aware about.

<a name="postconstruct_annotations"></a>
#### 1.3.1. PostConstruct Annotations

Some beans have methods, usually named `afterPropertiesSet()`, that are annotated with `@PostConstruct`. The `PostConstruct` annotation is a Java EE construct whose purpose is to indicate a method for bean initialization after the bean instance has been created and all its setters called. Spring, and some other framework supporting dependency injection, will invoke methods annotated with `PostConstruct` automatically, but if you are not using such a framework you need to remember to invoke these methods manually.

Suppose that we have the class `Foo`:

```
public class Foo {
  private Integer height;
  private Integer width;

  // setters and getters

  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (this.height == null || this.width == null) {
      throw new IllegalArgumentException("Must height and width must be set");
    }
  }  

}
```

If you "manually" create an instance of `Foo` you should then invoke `afterPropertiesSet` yourself. The methods annotated with `PostConstruct` do not only assert that everything is assigned, but may also assign default values or initialize the bean in other ways. Therefore, don't try to be clever and skip the `afterProperties`-invocation.

```
Foo bean = new Foo();
bean.setHeight(100);
bean.setWidth(200);
bean.afterProperties();
```

<a name="use_of_lombok"></a>
#### 1.3.2. Use of Lombok

Writing code and documentation for setters, getters och sometimes for a builder is really boring. Even if we are not lazy we prefer to spend our time in writing high quality business logic instead. Therefore we make use of [Lombok](https://projectlombok.org) in many places.

So, you probably want to set up your Java IDE to use Lombok if you are using the SignService Integration libraries in any of your products. The [Lombok setup guide](https://projectlombok.org/setup/overview) will assist you.

<a name="java_version_compatibility"></a>
#### 1.3.3. Java Version Compatibility

All SignService libraries are built with Java 8. This means that no specific functionality from later Java releases are used. Of course, you can set up your project to use a later Java version.

<a name="logging"></a>
#### 1.3.4. Logging

All the SignService libraries use the [Simple Logging Facade for Java (SLF4J)](http://www.slf4j.org).

So, if you use Java logging, log4j, logback or any other supported logging framework the logs from the SignService Integration libraries will be visible for you.

You have access to all source code so you'll figure out which packages to configure for logging, but for those of you that are a bit lazy, here's a brief listing:

- `se.idsec.signservice` - Main package for all SignService related code from IDsec.

- `se.swedenconnect` - The SignService Integration libraries make use of SAML and JAXB XML packages from Sweden Connect.

- `org.opensaml` - For handling some of the SAML objects that are part of the DSS protocol.

<a name="initializing_the_library"></a>
## 2. Initializing the Library

The SignService Integration libraries use the [Apache Santuario](https://santuario.apache.org) xmlsec library and [OpenSAML](https://wiki.shibboleth.net/confluence/display/OS30/Home) to implement things like XML signing and validation, encryption of sign messages using a recipient key found in SAML metadata, and more.

Unfortunately, these libraries must be initialized, and to some extent configured. Therefore, the SignService Integration Service needs to be initialized the first thing when your application starts.

The class [SignServiceIntegrationServiceInitializer](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/SignServiceIntegrationServiceInitializer.java) offers a simple way to initalize all underlying libraries that needs initializing.

[SignServiceIntegrationServiceInitializer](https://github.com/idsec-solutions/signservice-integration/blob/master/integration-impl/src/main/java/se/idsec/signservice/integration/SignServiceIntegrationServiceInitializer.java) defines two initializing methods:

- `initialize()` - Initializes OpenSAML and Apache xmlsec with default algorithm settings.

- `initialize(SecurityConfiguration)` - Initializes OpenSAML with the given security configuration.

If you are running in a environment that is according to the [Swedish eID Framework](https://docs.swedenconnect.se) you should pass in an instance of [SwedishEidSecurityConfiguration](https://github.com/litsec/swedish-eid-opensaml/blob/master/src/main/java/se/litsec/swedisheid/opensaml/xmlsec/config/SwedishEidSecurityConfiguration.java). This configuration sets up the default algorithms according to chapter 8, "Cryptographic Algorithms", of the [Deployment Profile for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html#cryptographic-algorithms).

<a name="spring_boot_example_2"></a>
### 2.1. Spring Boot Example

When running in a Spring Boot environment you can create a bean that initializes the SignService Integration library. But this bean really needs to be created before any other SignService Integration beans, so you would have to add a `@DependentOn` annotation just about everywhere.

A better solution is to create a `Component` and make sure it has the higest precedence (i.e., is created first). That way you can forget about dependent beans.

```
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SignServiceIntegrationInitComponent {

  public SignServiceIntegrationInitComponent() throws Exception {
    SignServiceIntegrationServiceInitializer.initialize(
      new SwedishEidSecurityConfiguration());
  }
}
```

<a name="initializing_manually"></a>
### 2.2. Initializing Manually

If you are not using a framework like Spring you need to make sure that the `SignServiceIntegrationServiceInitializer.initialize` call is made at application start up.

```
public class SignerApplication {

  public static void main(final String[] args) {
    try {
      SignServiceIntegrationServiceInitializer.initialize(
        new SwedishEidSecurityConfiguration());
    }
    catch (Exception e) {
      ... <report error>
    }
  }

}
```

---

Copyright &copy; 2019-2022, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
