/*
 * Copyright 2019-2020 IDsec Solutions AB
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
package se.idsec.signservice.integration.process.impl;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.dss.DSSStatusCodes;
import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.SignatureResult.SignatureResultBuilder;
import se.idsec.signservice.integration.authentication.SignerAssertionInformation;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.SignServiceProtocolException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.SignedDocument;
import se.idsec.signservice.integration.document.SignedDocumentProcessor;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.dss.DssUtils;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.idsec.signservice.integration.process.SignResponseProcessor;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.certificate.impl.SimpleCertificateValidator;
import se.idsec.signservice.security.sign.xml.XMLMessageSignatureValidator;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLMessageSignatureValidator;
import se.idsec.signservice.utils.AssertThat;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.idsec.signservice.xml.JAXBUnmarshaller;
import se.swedenconnect.schemas.csig.dssext_1_1.SignResponseExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.csig.dssext_1_1.SignatureCertificateChain;
import se.swedenconnect.schemas.dss_1_0.SignResponse;

/**
 * Default implementation of the {@link SignResponseProcessor} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignResponseProcessor implements SignResponseProcessor {
  
  /** The version to assume if no version has been set. */
  private final static String DEFAULT_VERSION = "1.1";

  /** For validating signatures on SignResponse messages. */
  private XMLMessageSignatureValidator signResponseSignatureValidator = new DefaultXMLMessageSignatureValidator();

  /** Needed when validating the SignResponse signatures. */
  private XMLSignatureLocation xmlSignatureLocation;

  /** The processors for handling the signed documents. */
  private List<SignedDocumentProcessor<?, ?>> signedDocumentProcessors;

  /** Processor for handling the signer assertion info. */
  private SignerAssertionInfoProcessor signerAssertionInfoProcessor;

  /** Processing config. */
  protected SignResponseProcessingConfig processingConfiguration;

  /**
   * An optional mapping between policies and certificate validators. It does not matter what trust anchor each
   * validator has been configured with since this will be explicitly set for each call. This information is taken from
   * the {@link IntegrationServiceConfiguration#getTrustAnchors()}.
   * <p>
   * If no mapping for a given policy exists, a default validator will be used (see {@link SimpleCertificateValidator}).
   * </p>
   */
  private Map<String, CertificateValidator> certificateValidators;

  /** The default certificate validator. This instance is used if no explicit mapping exists. */
  private CertificateValidator defaultCertificateValidator = new SimpleCertificateValidator();

  /**
   * Constructor.
   */
  public DefaultSignResponseProcessor() {
    try {
      this.xmlSignatureLocation = new XMLSignatureLocation("/*/*[local-name()='OptionalOutputs']", ChildPosition.LAST);
    }
    catch (XPathExpressionException e) {
      log.error("Failed to setup XPath for signature validation", e);
      throw new SecurityException("Failed to setup XPath for signature validation", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureResult processSignResponse(final String signResponse,
      final SignatureSessionState sessionState,
      final IntegrationServiceConfiguration config,
      final SignResponseProcessingParameters parameters)
      throws SignResponseCancelStatusException, SignResponseErrorStatusException, SignServiceIntegrationException {

    // First decode the encoded SignResponse ...
    //
    Document signResponseDocument;
    SignResponseWrapper response;
    try {
      signResponseDocument = DOMUtils.base64ToDocument(signResponse);
      if (log.isTraceEnabled()) {
        log.trace("{}: SignResponse: {}", CorrelationID.id(), DOMUtils.prettyPrint(signResponseDocument));
      }
      response = new SignResponseWrapper(JAXBUnmarshaller.unmarshall(signResponseDocument, SignResponse.class));

      // Make sure we can process this response ...
      if (!DssUtils.DSS_PROFILE.equals(response.getProfile())) {
        final String msg = String.format("Invalid SignResponse (RequestID: %s) - Expected Profile='%s' but was '%s'",
          response.getRequestID(), DssUtils.DSS_PROFILE, response.getProfile());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignServiceProtocolException(msg);
      }
    }
    catch (InternalXMLException | JAXBException e) {
      throw new SignServiceProtocolException("Failed to decode received SignResponse", e);
    }
    
    // Validate the signature of the SignResponse ...
    //
    try {
      this.signResponseSignatureValidator.validate(signResponseDocument, config.getSignServiceCertificatesInternal(),
        this.xmlSignatureLocation);
    }
    catch (SignatureException e) {
      final String msg = String.format("Failed to verify signature on SignResponse - %s", e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new SignResponseProcessingException(new ErrorCode.Code("signature"), msg, e);
    }

    // Make sure that the received message is in response to the passed request.
    //
    if (!sessionState.getSignRequest().getRequestID().equals(response.getRequestID())) {
      final String msg = String.format("RequestID in SignResponse '%s' does not match expected RequestID '%s'",
        response.getRequestID(), sessionState.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("mismatch-id"), msg);
    }

    // Check result ...
    //
    if (response.getResult() == null) {
      final String msg = "Received SignResponse is missing Result element";
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    if (!DSSStatusCodes.DSS_SUCCESS.equals(response.getResult().getResultMajor())) {
      log.info("{}: SignResponse with ID '{}' reported error: '{}' - '{}' - '{}'",
        CorrelationID.id(), response.getRequestID(), response.getResult().getResultMajor(),
        response.getResult().getResultMinor(),
        response.getResult().getResultMessage() != null ? response.getResult().getResultMessage().getValue() : "-");

      if (DSSStatusCodes.DSS_MINOR_USER_CANCEL.equals(response.getResult().getResultMinor())) {
        throw new SignResponseCancelStatusException();
      }
      throw new SignResponseErrorStatusException(response.getResult().getResultMajor(), response.getResult().getResultMinor(),
        response.getResult().getResultMessage() != null ? response.getResult().getResultMessage().getValue() : null);
    }
    
    // Check version of response ...
    //
    final String requestVersion = Optional.ofNullable(sessionState.getSignRequest().getSignRequestExtension().getVersion()).orElse(DEFAULT_VERSION);
    final String responseVersion = Optional.ofNullable(response.getSignResponseExtension().getVersion()).orElse(DEFAULT_VERSION);
    if (!requestVersion.equals(responseVersion)) {      
      // OK, this is an error. The response version MUST be set to the same version as the request version ...
      final String msg = String.format("Version of SignResponse (%s) does not equal version of SignRequest (%s)", 
        responseVersion, requestVersion);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("version"), msg);
    }

    // OK, it's a success.
    //
    // Next, validate the response ...
    //
    SignatureResultBuilder resultBuilder = SignatureResult.builder();
    resultBuilder
      .id(sessionState.getSignRequest().getRequestID())
      .correlationId(CorrelationID.id());

    final SignResponseExtension signResponseExtension = response.getSignResponseExtension();
    if (signResponseExtension == null) {
      final String msg = String.format("SignResponse does not contain SignResponseExtension [request-id='%s']",
        sessionState.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Verify that the response is not too old ...
    //
    this.validateResponseTime(signResponseExtension.getResponseTime(),
      sessionState.getSignRequest().getSignRequestExtension().getRequestTime(), sessionState.getSignRequest().getRequestID());

    // Make sure that the request bytes are there ...
    //
    this.validateReceivedRequest(signResponseExtension.getRequest(), sessionState.getSignRequest());

    // Get hold of the signer certificate chain ...
    //
    final List<X509Certificate> signerCertificateChain = this.getSignerCertificateChain(signResponseExtension
      .getSignatureCertificateChain(), sessionState.getSignRequest().getRequestID());

    // Let's validate the signer certificate
    //
    final CertificateValidator certificateValidator = this.getCertificateValidator(config.getPolicy());
    try {
      certificateValidator.validate(signerCertificateChain.get(0),
        signerCertificateChain.size() > 1 ? signerCertificateChain.subList(1, signerCertificateChain.size()) : null,
        null, config.getTrustAnchorsInternal());

      log.info("{}: Signer certificate successfully validated - {} [request-id='%s']",
        CorrelationID.id(), CertificateUtils.toLogString(signerCertificateChain.get(0)), sessionState.getSignRequest().getRequestID());
    }
    catch (GeneralSecurityException e) {
      final String msg = String.format("Validation of signer certificate failed - %s [request-id='%s']",
        e.getMessage(), sessionState.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-signercert"), msg, e);
    }

    // If we are using strict processing we assert that the user certificate contains what we expect ...
    //
    if (this.processingConfiguration.isStrictProcessing()) {
      // TODO: Validate that the user certificate looks ok ...
    }

    // Get the signer assertion information (and validate it).
    //
    final SignerAssertionInformation signerAssertionInformation = this.signerAssertionInfoProcessor.processSignerAssertionInfo(response,
      sessionState, parameters);
    resultBuilder.signerAssertionInformation(signerAssertionInformation);

    // Make sure that we got a sign task data for each TBS document ...
    //
    final SignTasks signTasks = response.getSignTasks();

    if (signTasks.getSignTaskDatas().size() != sessionState.getTbsDocuments().size()) {
      final String msg = String.format("SignResponse contains %d signatures, but %d was requested [request-id='%s']",
        signTasks.getSignTaskDatas().size(), sessionState.getTbsDocuments().size(), sessionState.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }

    // Now, iterate over all signatures and build signed documents and validate them ...
    //
    for (final SignTaskData signTaskData : signTasks.getSignTaskDatas()) {

      // Make sure the SignTaskData follows the specs and holds all required fields ...
      this.checkSignTaskData(signTaskData, sessionState.getSignRequest());

      // Find a processor for this object ...
      final SignedDocumentProcessor<?, ?> processor = this.signedDocumentProcessors.stream()
        .filter(p -> p.supports(signTaskData))
        .findFirst()
        .orElseThrow(() -> new InternalSignServiceIntegrationException(new ErrorCode.Code("config"), "Could not find document processor"));

      // Process the document ...
      final SignedDocument signedDocument = processDocument(processor, signTaskData, signerCertificateChain, sessionState, response,
        parameters);

      // Add it to the result ...
      resultBuilder.signedDocument(signedDocument);
    }

    return resultBuilder.build();
  }

  /**
   * Compiles a signed document and validates it.
   * 
   * @param processor
   *          the document processor
   * @param signTaskData
   *          the sign task data
   * @param signerCertificateChain
   *          the certificate chain
   * @param state
   *          the session state
   * @param signResponse
   *          the sign response
   * @param parameters
   *          optional processing parameters
   * @return a signed document
   * @throws SignServiceIntegrationException
   *           for processing errors
   */
  protected <T, X extends AdesObject> SignedDocument processDocument(final SignedDocumentProcessor<T, X> processor,
      final SignTaskData signTaskData,
      final List<X509Certificate> signerCertificateChain,
      final SignatureSessionState state,
      final SignResponseWrapper signResponse,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    // Find a corresponding TbsDocument ...
    final TbsDocument tbsDocument = this.getTbsDocument(signTaskData, state);

    // Build the signed document ...
    final CompiledSignedDocument<T, X> signedDocument = processor.buildSignedDocument(tbsDocument, signTaskData, signerCertificateChain,
      state.getSignRequest(), parameters);

    // Validate the signature of the document ...
    processor.validateSignedDocument(
      signedDocument.getDocument(), signerCertificateChain.get(0), signTaskData, parameters, state.getSignRequest().getRequestID());

    // Optionally, validate the XAdES object ...
    if (signedDocument.getAdesObject() != null) {
      processor.validateAdesObject(signedDocument.getAdesObject(), signerCertificateChain.get(0), signTaskData,
        state.getSignRequest(), signResponse, parameters);
    }

    return signedDocument.getSignedDocument();
  }

  /**
   * Validates the the response time from the SignResponse is valid. The method also ensures that the server processing
   * time hasn't exceeded or max limit.
   * 
   * @param responseTime
   *          the response time
   * @param requestTime
   *          the time when the request was sent
   * @param requestID
   *          the requestID (for logging)
   * @throws SignServiceIntegrationException
   *           for expired responses
   */
  protected void validateResponseTime(final XMLGregorianCalendar responseTime, final XMLGregorianCalendar requestTime,
      final String requestID) throws SignServiceIntegrationException {

    if (responseTime == null) {
      final String msg = String.format("SignResponse does not contain required ResponseTime [request-id='%s']", requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    final long responseTimeMillis = responseTime.toGregorianCalendar().getTimeInMillis();
    final long now = System.currentTimeMillis();

    // Has the response expired?
    //
    if ((now - responseTimeMillis - this.processingConfiguration.getAllowedClockSkew()) > this.processingConfiguration
      .getMaximumAllowedResponseAge()) {
      final String msg = String.format("SignResponse is too old. response-time:%d - current-time:%d - max-allowed-age:%d - " +
          "allowed-clock-skew:%d [request-id='%s']",
        responseTimeMillis, now, this.processingConfiguration.getMaximumAllowedResponseAge(),
        this.processingConfiguration.getAllowedClockSkew(), requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("expired-response"), msg);
    }

    // Also check the "not yet valid" case...
    //
    if ((responseTimeMillis - this.processingConfiguration.getAllowedClockSkew()) > now) {
      final String msg = String.format("SignResponse is not yet valid according to ResponseTime. response-time:%d - current-time:%d - " +
          "allowed-clock-skew:%d [request-id='%s']",
        responseTimeMillis, now, this.processingConfiguration.getAllowedClockSkew(), requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }

    // We also want to ensure that the server processing time hasn't exceeded or max limit ...
    // We don't have to care about clock skew since we were the ones that set the request time.
    //
    final long requestTimeMillis = requestTime.toGregorianCalendar().getTimeInMillis();
    if ((now - requestTimeMillis) > this.processingConfiguration.getMaximumAllowedProcessingTime()) {
      final String msg = String.format(
        "Server processing time exceeded allowed limit. request-time:%d - current-time:%d - limit:%d [request-id='%s']",
        requestTimeMillis, now, this.processingConfiguration.getMaximumAllowedProcessingTime(), requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("server-processing-time-exceeded-limit"), msg);
    }
  }

  /**
   * Validates the received Request element (throws only if strict processing is active).
   * 
   * @param request
   *          the received Request element
   * @param sentRequest
   *          the request that was actually sent
   * @throws SignServiceIntegrationException
   *           if the Request is not present or differs from what was sent
   */
  protected void validateReceivedRequest(final byte[] request, final SignRequestWrapper sentRequest)
      throws SignServiceIntegrationException {

    if (request == null || request.length == 0) {
      final String msg = String.format("SignResponse does not contain a Request element - this is required [request-id='%s']", sentRequest
        .getRequestID());
      if (this.processingConfiguration.isStrictProcessing()) {
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignServiceProtocolException(msg);
      }
      log.warn("{}: {}", CorrelationID.id(), msg);
    }

    // TODO: If strict processing is active compare this request with our request from the session state.
  }

  /**
   * Gets a list of {@link X509Certificate} by reading the supplied {@code SignatureCertificateChain}.
   * 
   * @param signatureCertificateChain
   *          the chain received in the response
   * @param requestID
   *          the request ID for the response
   * @return a list of X509Certificate objects
   * @throws SignServiceIntegrationException
   *           for decoding errors
   */
  protected List<X509Certificate> getSignerCertificateChain(
      final SignatureCertificateChain signatureCertificateChain, final String requestID) throws SignServiceIntegrationException {

    // First check that the response contains the signer certificate and the chain ...
    //
    if (signatureCertificateChain == null || !signatureCertificateChain.isSetX509Certificates()) {
      final String msg = String.format("Missing signer certificate chain from SignResponse [request-id='%s']", requestID);
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Next, decode all certificates ...
    //
    List<X509Certificate> certificates = new ArrayList<>();
    for (byte[] enc : signatureCertificateChain.getX509Certificates()) {
      try {
        certificates.add(CertificateUtils.decodeCertificate(enc));
      }
      catch (CertificateException e) {
        final String msg = String.format("Failed to decode certificate in SignatureCertificateChain of SignResponse [request-id='%s']",
          requestID);
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
      }
    }

    return certificates;
  }

  /**
   * Make checks that the supplied {@code SignTaskData} object follows the specs.
   * 
   * @param signTaskData
   *          the object to check
   * @param signRequest
   *          the sign request corresponding to the response in which we received the SignTaskData
   * @throws SignServiceIntegrationException
   *           for validation errors
   */
  protected void checkSignTaskData(final SignTaskData signTaskData, final SignRequestWrapper signRequest)
      throws SignServiceIntegrationException {

    // Make sure we have a Task-ID ...
    //
    if (signTaskData.getSignTaskId() == null) {
      final String msg = String.format("Missing SignTaskId for signed document [request-id='%s']", signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Type is required ...
    //
    if (signTaskData.getSigType() == null) {
      final String msg = String.format("Missing SigType for signed document with ID '%s' [request-id='%s']",
        signTaskData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // The ToBeSignedBytes are required ...
    //
    if (signTaskData.getToBeSignedBytes() == null || signTaskData.getToBeSignedBytes().length == 0) {
      final String msg = String.format("Missing ToBeSignedBytes for signed document with ID '%s' [request-id='%s']",
        signTaskData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }

    // Make checks about the signature ...
    //
    if (signTaskData.getBase64Signature() == null
        || signTaskData.getBase64Signature().getValue() == null
        || signTaskData.getBase64Signature().getValue().length == 0) {
      final String msg = String.format("Sign task '%s' is missing signature [request-id='%s']",
        signTaskData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignServiceProtocolException(msg);
    }
    if (signTaskData.getBase64Signature().getType() != null) {
      if (!signTaskData.getBase64Signature()
        .getType()
        .equals(
          signRequest.getSignRequestExtension().getRequestedSignatureAlgorithm())) {
        final String msg = String.format(
          "Signature algorithm used for sign task '%s' does not match requested signature '%s' [request-id='%s']",
          signTaskData.getSignTaskId(), signTaskData.getBase64Signature().getType(),
          signRequest.getSignRequestExtension().getRequestedSignatureAlgorithm(), signRequest.getRequestID());
        log.error("{}: {}", CorrelationID.id(), msg);
        throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
      }
    }
  }

  /**
   * Given a {@code SignTaskData} the method finds the corresponding TBS document from the session state.
   * 
   * @param signTaskData
   *          the signature
   * @param state
   *          the state holding the TBS documents
   * @return a TbsDocument
   * @throws SignServiceIntegrationException
   *           if no matching TBS document is found
   */
  protected TbsDocument getTbsDocument(final SignTaskData signTaskData, final SignatureSessionState state)
      throws SignServiceIntegrationException {

    // Locate the matching TBS document from the session state ...
    //
    final TbsDocument tbsDocument = state.getTbsDocuments()
      .stream()
      .filter(d -> d.getId().equals(signTaskData.getSignTaskId()))
      .findFirst()
      .orElse(null);

    if (tbsDocument == null) {
      final String msg = String.format(
        "SignResponse contains SignTask with ID '%s' - This ID does not appear in SignRequest [request-id='%s']",
        signTaskData.getSignTaskId(), state.getSignRequest().getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("invalid-response"), msg);
    }

    return tbsDocument;
  }

  /**
   * Gets a certificate validator that is to be used to perform a certificate validation according to the supplied
   * policy.
   * 
   * @param policy
   *          the policy
   * @return a certificate validator
   */
  private CertificateValidator getCertificateValidator(final String policy) {
    CertificateValidator validator = this.certificateValidators != null ? this.certificateValidators.get(policy) : null;
    return validator != null ? validator : this.defaultCertificateValidator;
  }

  /**
   * Assigns the processors for handling the signed documents.
   * 
   * @param signedDocumentProcessors
   *          document processors
   */
  public void setSignedDocumentProcessors(final List<SignedDocumentProcessor<?, ?>> signedDocumentProcessors) {
    this.signedDocumentProcessors = signedDocumentProcessors;
  }

  /**
   * Assigns the processor for handling the signer assertion info from the sign response. If not assigned an instance of
   * {@link DefaultSignerAssertionInfoProcessor} will be used.
   * 
   * @param signerAssertionInfoProcessor
   *          signer assertion info processor
   */
  public void setSignerAssertionInfoProcessor(final SignerAssertionInfoProcessor signerAssertionInfoProcessor) {
    this.signerAssertionInfoProcessor = signerAssertionInfoProcessor;
  }

  /**
   * Assigns the processing config settings.
   * 
   * @param processingConfiguration
   *          the processing config settings
   */
  public void setProcessingConfiguration(final SignResponseProcessingConfig processingConfiguration) {
    this.processingConfiguration = processingConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public SignResponseProcessingConfig getProcessingConfiguration() {
    return this.processingConfiguration;
  }

  /**
   * Assigns a mapping between policies and certificate validators. It does not matter what trust anchor each validator
   * has been configured with since this will be explicitly set for each call. This information is taken from the
   * {@link IntegrationServiceConfiguration#getTrustAnchors()}.
   * <p>
   * If no mapping for a given policy exists, a default validator will be used (see {@link SimpleCertificateValidator}).
   * </p>
   * 
   * @param certificateValidators
   *          policy to certificate validator mappings
   */
  public void setCertificateValidators(final Map<String, CertificateValidator> certificateValidators) {
    this.certificateValidators = certificateValidators;
  }

  /**
   * Ensures that all required properties have been assigned. The method also makes sure that the
   * {@code processingConfiguration} property is assigned (by default
   * {@link SignResponseProcessingConfig#defaultSignResponseProcessingConfig()} is used) and that
   * {@code signerAssertionInfoProcessor} is set (by default a {@link DefaultSignerAssertionInfoProcessor} is used).
   * 
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   * 
   * @throws Exception
   *           if not all settings are correct
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    AssertThat.isNotEmpty(this.signedDocumentProcessors, "At least one document processor must be configured");
    if (this.processingConfiguration == null) {
      this.processingConfiguration = SignResponseProcessingConfig.defaultSignResponseProcessingConfig();
    }
    if (this.signerAssertionInfoProcessor == null) {
      DefaultSignerAssertionInfoProcessor p = new DefaultSignerAssertionInfoProcessor();
      p.setProcessingConfig(this.processingConfiguration);
      this.signerAssertionInfoProcessor = p;
    }
  }

}
