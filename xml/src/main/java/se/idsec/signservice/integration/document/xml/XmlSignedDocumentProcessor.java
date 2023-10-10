/*
 * Copyright 2019-2023 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.signservice.integration.document.xml;

import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractSignedDocumentProcessor;
import se.idsec.signservice.integration.document.impl.DefaultCompiledSignedDocument;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.impl.SignResponseProcessingException;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSignatureValidator;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Signed document processor for XML documents.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XmlSignedDocumentProcessor extends AbstractSignedDocumentProcessor<Document, XadesQualifyingProperties> {

  /** The document decoder. */
  private static final XmlDocumentEncoderDecoder documentEncoderDecoder = new XmlDocumentEncoderDecoder();

  /** Prefix for the XMLDSig namespace. */
  private static final String DS_PREFIX = XMLSignature.getDefaultPrefix(Constants.SignatureSpecNS);

  /** {@inheritDoc} */
  @Override
  public boolean supports(final SignTaskData signData) {
    return "XML".equalsIgnoreCase(signData.getSigType());
  }

  /** {@inheritDoc} */
  @Override
  public CompiledSignedDocument<Document, XadesQualifyingProperties> buildSignedDocument(
      final TbsDocument tbsDocument,
      final SignTaskData signedData,
      final List<X509Certificate> signerCertificateChain,
      final SignRequestWrapper signRequest,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    log.debug("{}: Compiling signed XML document for Sign task '{}' ... [request-id='{}']",
        CorrelationID.id(), signedData.getSignTaskId(), signRequest.getRequestID());

    // First decode the original input document into a document object ...
    //
    final Document document = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());

    // We need to figure out where in the document the signature should be installed.
    // By default it is added as the last child element of the document root, but the parameters
    // may override this ...
    //
    final se.idsec.signservice.security.sign.xml.XMLSignatureLocation signatureLocation =
        this.getAndValidateXMLSignatureLocation(parameters, document);

    // Create Signature object ...
    //
    final Element signatureElement =
        document.createElementNS(Constants.SignatureSpecNS, qualifiedName(Constants._TAG_SIGNATURE));
    if (signedData.getAdESObject() != null && signedData.getAdESObject().getSignatureId() != null) {
      signatureElement.setAttribute(Constants._ATT_ID, signedData.getAdESObject().getSignatureId());
    }

    // Add the SignedInfo ...
    //
    final Element signedInfo = this.getSignedInfo(signedData, signRequest.getRequestID());
    if (log.isTraceEnabled()) {
      log.trace("{}: SignedInfo for sign task '{}': {}", CorrelationID.id(), signedData.getSignTaskId(),
          DOMUtils.prettyPrint(signedInfo));
    }
    signatureElement.appendChild(document.importNode(signedInfo, true));

    // Create SignatureValue ...
    //
    final Element signatureValueElement =
        document.createElementNS(Constants.SignatureSpecNS, qualifiedName(Constants._TAG_SIGNATUREVALUE));
    signatureValueElement
        .setTextContent(Base64.getEncoder().encodeToString(signedData.getBase64Signature().getValue()));
    signatureElement.appendChild(signatureValueElement);

    // Save certificates under the KeyInfo/X509Data element ...
    //
    final Element keyInfoElement =
        document.createElementNS(Constants.SignatureSpecNS, qualifiedName(Constants._TAG_KEYINFO));
    signatureElement.appendChild(keyInfoElement);

    final Element x509DataElement =
        document.createElementNS(Constants.SignatureSpecNS, qualifiedName(Constants._TAG_X509DATA));
    keyInfoElement.appendChild(x509DataElement);

    for (final X509Certificate cert : signerCertificateChain) {
      final Element certElement =
          document.createElementNS(Constants.SignatureSpecNS, qualifiedName(Constants._TAG_X509CERTIFICATE));
      try {
        certElement.setTextContent(Base64.getEncoder().encodeToString(cert.getEncoded()));
        x509DataElement.appendChild(certElement);
      }
      catch (final CertificateEncodingException e) {
        // Should not happen - The certs have been checked already ...
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), "Invalid certificate", e);
      }
    }

    // If this is a XAdES signature, also set this object ...
    //
    XadesQualifyingProperties xadesObject = null;

    if (signedData.getAdESObject() != null && signedData.getAdESObject().isSetAdESObjectBytes()) {
      final Element dsObject = this.getDsObject(signedData, signRequest.getRequestID());
      if (log.isTraceEnabled()) {
        log.trace("{}: XAdES ds:Object for sign task '{}': {}", CorrelationID.id(), signedData.getSignTaskId(),
            DOMUtils.prettyPrint(dsObject));
      }
      signatureElement.appendChild(document.importNode(dsObject, true));

      // Get hold of the XadesQualifyingProperties element ...
      xadesObject = XadesQualifyingProperties.createXadesQualifyingProperties(dsObject);
    }

    // OK, time to insert the signature into the document ...
    //
    try {
      signatureLocation.insertSignature(signatureElement, document);
    }
    catch (final XPathExpressionException e) {
      // Should never happen since we already tested the XPath expression ...
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), "Failed to create Signature",
          e);
    }

    if (log.isDebugEnabled()) {
      log.debug("{}: Signature for sign task '{}': {}", CorrelationID.id(), signedData.getSignTaskId(),
          DOMUtils.prettyPrint(signatureElement));
    }

    return new DefaultCompiledSignedDocument<>(
        signedData.getSignTaskId(), document, DocumentType.XML.getMimeType(), this.getDocumentEncoder(), xadesObject);
  }

  /** {@inheritDoc} */
  @Override
  public void validateSignedDocument(final Document signedDocument,
      final X509Certificate signerCertificate,
      final SignTaskData signTaskData,
      final SignResponseProcessingParameters parameters,
      final String requestID) throws SignServiceIntegrationException {

    log.debug("{}: Validating signed XML document for Sign task '{}' ... [request-id='{}']",
        CorrelationID.id(), signTaskData.getSignTaskId(), requestID);

    // Get the location for the signature ...
    //
    final se.idsec.signservice.security.sign.xml.XMLSignatureLocation signatureLocation =
        this.getXMLSignatureLocation(parameters);

    final DefaultXMLSignatureValidator validator = new DefaultXMLSignatureValidator(signerCertificate);

    try {
      final SignatureValidationResult result = validator.validate(signedDocument, signatureLocation).get(0);
      if (!result.isSuccess()) {
        final String msg = String.format("Signature validation failed for sign task '%s' - %s - %s [request-id='%s']",
            signTaskData.getSignTaskId(), result.getStatus(), result.getStatusMessage(), requestID);
        log.error("{}: {}", CorrelationID.id());
        throw new DocumentProcessingException(new ErrorCode.Code("invalid-signature"), msg, result.getException());
      }
      log.debug("{}: Signature validation for sign task '%s' succeeded", CorrelationID.id(),
          signTaskData.getSignTaskId());
    }
    catch (final SignatureException e) {
      final String msg = String.format("Signature validation failed for sign task '%s' - %s [request-id='%s']",
          signTaskData.getSignTaskId(), e.getMessage(), requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new DocumentProcessingException(new ErrorCode.Code("invalid-signature"), msg, e);
    }
  }

  /**
   * Validates that the {@code xades:SigningTime} is valid.
   */
  @Override
  protected void performAdditionalAdesValidation(final XadesQualifyingProperties adesObject,
      final X509Certificate signingCertificate,
      final SignTaskData signTaskData, final SignRequestWrapper signRequest, final SignResponseWrapper signResponse,
      final SignResponseProcessingParameters parameters) throws DocumentProcessingException {

    try {
      final Long signingTime = adesObject.getSigningTime();
      if (signingTime == null) {
        final String msg =
            String.format("No SigningTime available in XAdES object for sign task '%s' [request-id='%s']",
                signTaskData.getSignTaskId(), signRequest.getRequestID());
        log.warn("{}: {}", CorrelationID.id(), msg);
        if (this.getProcessingConfiguration().isStrictProcessing()) {
          throw new DocumentProcessingException(new ErrorCode.Code("invalid-ades-object"), msg);
        }
        else {
          return;
        }
      }
      // SigningTime must be before the response time ...
      //
      final long responseTime =
          signResponse.getSignResponseExtension().getResponseTime().toGregorianCalendar().getTimeInMillis();
      if (signingTime > responseTime) {
        final String msg = String.format(
            "Invalid SigningTime (%d) in XAdES object for sign task '%s' - it is after response time (%d) [request-id='%s']",
            signingTime, signTaskData.getSignTaskId(), responseTime, signRequest.getRequestID());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new DocumentProcessingException(new ErrorCode.Code("invalid-ades-object"), msg);
      }

      // SigningTime must not be before request time ...
      //
      final long requestTime =
          signRequest.getSignRequestExtension().getRequestTime().toGregorianCalendar().getTimeInMillis();
      if (requestTime < signingTime - this.getProcessingConfiguration().getAllowedClockSkew()) {
        final String msg = String.format(
            "Invalid SigningTime (%d) in XAdES object for sign task '%s' - it is before request time (%d) [request-id='%s']",
            signingTime, signTaskData.getSignTaskId(), requestTime, signRequest.getRequestID());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new DocumentProcessingException(new ErrorCode.Code("invalid-ades-object"), msg);
      }

      log.debug("{}: Successfully validated SigningTime in XAdES object for sign task '%s' [request-id='%s']",
          CorrelationID.id(), signTaskData.getSignTaskId(), signRequest.getRequestID());
    }
    catch (final SignServiceProtocolException e) {
      throw new DocumentProcessingException(new ErrorCode.Code("invalid-ades-object"), e.getMessage(), e);
    }
  }

  /**
   * Creates a qualified name with the ds prefix.
   *
   * @param localName the element local name
   * @return a qualified name
   */
  private static String qualifiedName(final String localName) {
    return String.format("%s:%s", DS_PREFIX, localName);
  }

  /**
   * Extracts the {@code ds:SignedInfo} element from the supplied sign task data.
   *
   * @param signedData the object holding the SignedInfo element
   * @param requestID the request ID (for logging)
   * @return a SignedInfo element
   * @throws SignResponseProcessingException for errors extracting the SignedInfo
   */
  private Element getSignedInfo(final SignTaskData signedData, final String requestID)
      throws SignResponseProcessingException {
    try {
      final Element signedInfo = DOMUtils.bytesToDocument(signedData.getToBeSignedBytes()).getDocumentElement();
      if (!Constants._TAG_SIGNEDINFO.equals(signedInfo.getLocalName())) {
        final String msg = String.format(
            "Invalid ToBeSignedBytes of sign task '%s' - Expected SignedInfo but was %s [request-id='%s']",
            signedData.getSignTaskId(), signedInfo.getLocalName(), requestID);
        log.error("{}: {}", msg);
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
      }
      return signedInfo;
    }
    catch (final RuntimeException e) {
      final String msg =
          String.format("Invalid ToBeSignedBytes of sign task '%s' - Failed to unmarshall - %s [request-id='%s']",
              signedData.getSignTaskId(), e.getMessage(), requestID);
      log.error("{}: {}", msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg, e);
    }
  }

  /**
   * Extracts the {@code ds:Object} containing the {@code xades:QualifyingProperties} element from the supplied sign
   * task data.
   *
   * @param signedData the object holding the ds:Object element
   * @param requestID the request ID (for logging)
   * @return an ds:Object element
   * @throws SignResponseProcessingException for errors extracting the ds:Object
   */
  private Element getDsObject(final SignTaskData signedData, final String requestID)
      throws SignResponseProcessingException {
    try {
      final Element dsObjectElement =
          DOMUtils.bytesToDocument(signedData.getAdESObject().getAdESObjectBytes()).getDocumentElement();
      if (!Constants._TAG_OBJECT.equals(dsObjectElement.getLocalName())) {
        final String msg =
            String.format("Invalid AdESObjectBytes of sign task '%s' - Expected ds:Object but was %s [request-id='%s']",
                signedData.getSignTaskId(), dsObjectElement.getLocalName(), requestID);
        log.error("{}: {}", msg);
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
      }
      return dsObjectElement;
    }
    catch (final RuntimeException e) {
      final String msg =
          String.format("Invalid AdESObjectBytes of sign task '%s' - Failed to unmarshall - %s [request-id='%s']",
              signedData.getSignTaskId(), e.getMessage(), requestID);
      log.error("{}: {}", msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg, e);
    }
  }

  /**
   * Checks if the processing parameters contains an XPath expression telling where the signature should be installed,
   * otherwise creates a default location.
   *
   * @param parameters processing parameters
   * @return signature location object
   * @throws InputValidationException for invalid expressions
   */
  private se.idsec.signservice.security.sign.xml.XMLSignatureLocation getXMLSignatureLocation(
      final SignResponseProcessingParameters parameters) throws IllegalArgumentException {

    if (parameters == null || parameters.getXmlSignatureLocation() == null) {
      return new se.idsec.signservice.security.sign.xml.XMLSignatureLocation();
    }
    try {
      final XMLSignatureLocation.ChildPosition child = parameters.getXmlSignatureLocation().getChildPosition() != null
          ? XMLSignatureLocation.ChildPosition.fromPosition(parameters.getXmlSignatureLocation().getChildPosition())
          : XMLSignatureLocation.ChildPosition.LAST;

      final se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition _child =
          child == XMLSignatureLocation.ChildPosition.FIRST
              ? se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition.FIRST
              : se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition.LAST;

      final se.idsec.signservice.security.sign.xml.XMLSignatureLocation sigLoc =
          StringUtils.isNotBlank(parameters.getXmlSignatureLocation().getXPath())
              ? new se.idsec.signservice.security.sign.xml.XMLSignatureLocation(
                  parameters.getXmlSignatureLocation().getXPath(), _child)
              : new se.idsec.signservice.security.sign.xml.XMLSignatureLocation(_child);

      return sigLoc;
    }
    catch (final Exception e) {
      final String msg =
          String.format("Invalid expression supplied in SignResponseProcessingParameters/xmlSignatureLocation - %s",
              e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new IllegalArgumentException(e.getMessage(), e);
    }
  }

  /**
   * Checks if the processing parameters contains an XPath expression telling where the signature should be installed.
   * If so, it tests whether this expression is valid given the TBS document.
   *
   * @param parameters processing parameters
   * @param tbsDocument the document
   * @return signature location object
   * @throws InputValidationException for invalid expressions
   */
  private se.idsec.signservice.security.sign.xml.XMLSignatureLocation getAndValidateXMLSignatureLocation(
      final SignResponseProcessingParameters parameters, final Document tbsDocument)
      throws InputValidationException {

    try {
      final se.idsec.signservice.security.sign.xml.XMLSignatureLocation sigLoc =
          this.getXMLSignatureLocation(parameters);

      // Try it out
      sigLoc.testInsert(tbsDocument);

      return sigLoc;
    }
    catch (final Exception e) {
      final String msg =
          String.format("Invalid expression supplied in SignResponseProcessingParameters/xmlSignatureLocation - %s",
              e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new InputValidationException("parameters.xmlSignatureLocation", msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<Document> getDocumentDecoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<Document> getDocumentEncoder() {
    return documentEncoderDecoder;
  }

}
