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
package se.idsec.signservice.integration.process.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.annotation.PostConstruct;
import jakarta.xml.bind.JAXBException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.DocumentCache;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;
import se.idsec.signservice.integration.dss.DssUtils;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.process.SignRequestProcessingResult;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.idsec.signservice.integration.signmessage.SignMessageMimeType;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.idsec.signservice.integration.signmessage.SignMessageProcessor;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.utils.AssertThat;
import se.idsec.signservice.utils.ProtocolVersion;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.saml_2_0.assertion.AudienceRestriction;
import se.swedenconnect.schemas.saml_2_0.assertion.Conditions;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.xml.jaxb.JAXBMarshaller;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;
import java.io.Serial;
import java.security.SignatureException;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * Default implementation of the {@link SignRequestProcessor} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignRequestProcessor implements SignRequestProcessor {

  /** Processors for different TBS documents. */
  private List<TbsDocumentProcessor<?>> tbsDocumentProcessors;

  /** Validator. */
  private final SignRequestInputValidator signRequestInputValidator = new SignRequestInputValidator();

  /** Document cache. */
  private DocumentCache documentCache;

  /** The processor for SignMessages. */
  private SignMessageProcessor signMessageProcessor;

  /** Object factory for DSS objects. */
  private static final se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory =
      new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** Object factory for DSS-Ext objects. */
  private static final se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtObjectFactory =
      new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();

  /** Needed when signing the sign request. */
  private final XMLSignatureLocation xmlSignatureLocation;

  /**
   * The default version to use. If not set, section 3.1 of "DSS Extension for Federated Central Signing Services"
   * states that version 1.1 is the default. So, if the {@code defaultVersion} is not set, we don't include the version
   * unless a feature that requires a higher version is used.
   */
  private ProtocolVersion defaultVersion;

  /** Version 1.4. */
  private static final ProtocolVersion VERSION_1_4 = new ProtocolVersion("1.4");

  /** Constants for conditions. */
  private static final javax.xml.datatype.Duration ONE_MINUTE_BACK;
  private static final javax.xml.datatype.Duration FIVE_MINUTES_FORWARD;

  static {
    try {
      ONE_MINUTE_BACK = DatatypeFactory.newInstance().newDuration(-60000L);
      FIVE_MINUTES_FORWARD = DatatypeFactory.newInstance().newDuration(300000L);
    }
    catch (final DatatypeConfigurationException e) {
      throw new SecurityException(e);
    }
  }

  /**
   * Constructor.
   */
  public DefaultSignRequestProcessor() {
    try {
      this.xmlSignatureLocation = new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);
    }
    catch (final XPathExpressionException e) {
      log.error("Failed to setup XPath for signature inclusion", e);
      throw new SecurityException("Failed to setup XPath for signature inclusion", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestInput preProcess(final SignRequestInput signRequestInput,
      final IntegrationServiceConfiguration config, final String callerId) throws InputValidationException {

    // First validate ...
    //
    this.signRequestInputValidator.validateObject(signRequestInput, "signRequestInput", config);

    // Then apply default values ...
    //
    final SignRequestInput.SignRequestInputBuilder inputBuilder = signRequestInput.toBuilder();

    if (StringUtils.isBlank(signRequestInput.getCorrelationId())) {
      log.debug("No correlation ID provided in SignRequestInput, using '{}'", CorrelationID.id());
      inputBuilder.correlationId(CorrelationID.id());
    }

    // Policy
    if (signRequestInput.getPolicy() == null) {
      log.debug("{}: No policy given in input, using '{}'", CorrelationID.id(), config.getPolicy());
      inputBuilder.policy(config.getPolicy());
    }

    // SignRequesterID
    if (signRequestInput.getSignRequesterID() == null) {
      log.debug("{}: No signRequesterID given in input, using '{}'", CorrelationID.id(),
          config.getDefaultSignRequesterID());
      inputBuilder.signRequesterID(config.getDefaultSignRequesterID());
    }

    // ReturnUrl
    if (signRequestInput.getReturnUrl() == null) {
      log.debug("{}: No returnUrl given in input, using '{}'", CorrelationID.id(), config.getDefaultReturnUrl());
      inputBuilder.returnUrl(config.getDefaultReturnUrl());
    }

    // DestinationUrl
    if (signRequestInput.getDestinationUrl() == null) {
      log.debug("{}: No destinationUrl given in input, using '{}'", CorrelationID.id(),
          config.getDefaultDestinationUrl());
      inputBuilder.destinationUrl(config.getDefaultDestinationUrl());
    }

    // SignatureAlgorithm
    if (signRequestInput.getSignatureAlgorithm() == null) {
      log.debug("{}: No signatureAlgorithm given in input, using '{}'", CorrelationID.id(),
          config.getDefaultSignatureAlgorithm());
      inputBuilder.signatureAlgorithm(config.getDefaultSignatureAlgorithm());
    }

    // AuthnRequirements
    //
    final AuthnRequirements authnRequirements = signRequestInput.getAuthnRequirements() != null
        ? signRequestInput.getAuthnRequirements().toBuilder().build()
        : new AuthnRequirements();

    String authnServiceID = authnRequirements.getAuthnServiceID();
    if (authnServiceID == null) {
      log.debug("{}: No authnRequirements.authnServiceID given in input, using '{}'", CorrelationID.id(),
          config.getDefaultAuthnServiceID());
      authnRequirements.setAuthnServiceID(config.getDefaultAuthnServiceID());
      authnServiceID = config.getDefaultAuthnServiceID();
    }
    if (authnRequirements.getAuthnContextClassRefs() == null
        || authnRequirements.getAuthnContextClassRefs().isEmpty()) {
      log.debug("{}: No authnRequirements.authnContextClassRefs given in input, using '{}'",
          CorrelationID.id(), config.getDefaultAuthnContextRef());
      authnRequirements.setAuthnContextClassRefs(Collections.singletonList(config.getDefaultAuthnContextRef()));
    }
    if (authnRequirements.getRequestedSignerAttributes() == null
        || authnRequirements.getRequestedSignerAttributes().isEmpty()) {
      log.info("{}: No requested signer attributes specified - \"anonymous signature\"", CorrelationID.id());
    }
    inputBuilder.authnRequirements(authnRequirements);

    // SigningCertificateRequirements
    //
    if (signRequestInput.getCertificateRequirements() == null) {
      log.debug("{}: No certificateRequirements given in input, using {}", CorrelationID.id(),
          config.getDefaultCertificateRequirements());
      inputBuilder.certificateRequirements(config.getDefaultCertificateRequirements());
    }
    else {
      if (signRequestInput.getCertificateRequirements().getCertificateType() == null) {
        log.debug("{}: No certificateRequirements.certificateType given in input, using {}",
            CorrelationID.id(), config.getDefaultCertificateRequirements().getCertificateType());
        final SigningCertificateRequirements scr = signRequestInput.getCertificateRequirements();
        scr.setCertificateType(config.getDefaultCertificateRequirements().getCertificateType());
        inputBuilder.certificateRequirements(scr);
      }
      if (signRequestInput.getCertificateRequirements().getAttributeMappings() == null
          || signRequestInput.getCertificateRequirements().getAttributeMappings().isEmpty()) {
        log.debug("{}: No certificateRequirements.certificateType given in input, using {}",
            CorrelationID.id(), config.getDefaultCertificateRequirements().getAttributeMappings());
        final SigningCertificateRequirements scr = signRequestInput.getCertificateRequirements();
        scr.setAttributeMappings(config.getDefaultCertificateRequirements().getAttributeMappings());
        inputBuilder.certificateRequirements(scr);
      }
    }

    // TbsDocuments
    //
    // For each document that is to be signed, invoke a matching processor and pre-process it ...
    //
    inputBuilder.clearTbsDocuments();
    int pos = 0;
    for (final TbsDocument doc : signRequestInput.getTbsDocuments()) {
      final String fieldName = "signRequestInput.tbsDocuments[" + pos++ + "]";
      final TbsDocumentProcessor<?> processor = this.tbsDocumentProcessors.stream()
          .filter(p -> p.supports(doc))
          .findFirst()
          .orElseThrow(() -> new InputValidationException(fieldName,
              String.format("Document of type '%s' is not supported", doc.getMimeType())));

      final ProcessedTbsDocument processedTbsDocument = processor.preProcess(
          doc, signRequestInput, config, this.documentCache, callerId, fieldName);

      if (processedTbsDocument.getDocumentObject() != null) {
        final Extension ext = processedTbsDocument.getTbsDocument().getExtension();
        final DocumentExtension docExt = ext == null ? new DocumentExtension() : new DocumentExtension(ext);
        docExt.setDocument(processedTbsDocument.getDocumentObject());
        processedTbsDocument.getTbsDocument().setExtension(docExt);
      }

      inputBuilder.tbsDocument(processedTbsDocument.getTbsDocument());
    }

    // SignMessageParameters
    //
    if (signRequestInput.getSignMessageParameters() != null) {
      SignMessageParameters.SignMessageParametersBuilder smpBuilder = null;
      if (signRequestInput.getSignMessageParameters().getMimeType() == null) {
        log.debug("{}: No signMessageParameters.mimeType given in input, using {}",
            CorrelationID.id(), SignMessageMimeType.TEXT.getMimeType());
        smpBuilder = signRequestInput.getSignMessageParameters().toBuilder();
        smpBuilder.mimeType(SignMessageMimeType.TEXT);
      }
      if (signRequestInput.getSignMessageParameters().getMustShow() == null) {
        log.debug("{}: signMessageParameters.mustShow not set, defaulting to false", CorrelationID.id());
        if (smpBuilder == null) {
          smpBuilder = signRequestInput.getSignMessageParameters().toBuilder();
        }
        smpBuilder.mustShow(false);
      }
      if (signRequestInput.getSignMessageParameters().isPerformEncryption()
          && signRequestInput.getSignMessageParameters().getDisplayEntity() == null) {
        log.debug("{}: signMessageParameters.displayEntity is not set in input, defaulting to {}",
            CorrelationID.id(), authnServiceID);
        if (smpBuilder == null) {
          smpBuilder = signRequestInput.getSignMessageParameters().toBuilder();
        }
        smpBuilder.displayEntity(authnServiceID);
      }
      if (smpBuilder != null) {
        inputBuilder.signMessageParameters(smpBuilder.build());
      }
    }

    return inputBuilder.build();
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestProcessingResult process(
      final SignRequestInput signRequestInput, final String requestID, final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {

    // Start building the SignRequest ...
    //
    final SignRequestWrapper signRequest = new SignRequestWrapper(dssObjectFactory.createSignRequest());
    signRequest.setProfile(DssUtils.DSS_PROFILE);
    signRequest.setRequestID(requestID);

    final SignRequestExtension signRequestExtension = dssExtObjectFactory.createSignRequestExtension();

    // Version
    //
    if (this.defaultVersion != null) {
      signRequestExtension.setVersion(this.defaultVersion.toString());
    }

    // RequestTime
    //
    signRequestExtension.setRequestTime(getNow());

    // Conditions
    //
    final Conditions conditions = new Conditions();
    final XMLGregorianCalendar currentTime = getNow();
    // TODO: make configurable
    final XMLGregorianCalendar notBefore = (XMLGregorianCalendar) currentTime.clone();
    notBefore.add(ONE_MINUTE_BACK);
    conditions.setNotBefore(notBefore);
    final XMLGregorianCalendar notAfter = (XMLGregorianCalendar) currentTime.clone();
    notAfter.add(FIVE_MINUTES_FORWARD);
    conditions.setNotOnOrAfter(notAfter);

    final AudienceRestriction audienceRestriction = new AudienceRestriction();
    audienceRestriction.getAudiences().add(signRequestInput.getReturnUrl());
    conditions.getConditionsAndAudienceRestrictionsAndOneTimeUses().add(audienceRestriction);

    signRequestExtension.setConditions(conditions);

    // Signer
    //
    if (signRequestInput.getAuthnRequirements().getRequestedSignerAttributes() != null
        && !signRequestInput.getAuthnRequirements().getRequestedSignerAttributes().isEmpty()) {

      signRequestExtension.setSigner(
          DssUtils.toAttributeStatement(signRequestInput.getAuthnRequirements().getRequestedSignerAttributes()));
    }

    // IdentityProvider
    //
    signRequestExtension
        .setIdentityProvider(DssUtils.toEntity(signRequestInput.getAuthnRequirements().getAuthnServiceID()));

    // AuthnProfile
    //
    if (!StringUtils.isBlank(signRequestInput.getAuthnRequirements().getAuthnProfile())) {
      if (signRequestExtension.getVersion() != null && VERSION_1_4.compareTo(signRequestExtension.getVersion()) > 0) {
        log.info("AuthnProfile is set. Setting version of SignRequest to 1.4 ...");
        signRequestExtension.setVersion("1.4");
        signRequestExtension.setAuthnProfile(signRequestInput.getAuthnRequirements().getAuthnProfile());
      }
    }

    // SignRequester
    //
    signRequestExtension.setSignRequester(DssUtils.toEntity(signRequestInput.getSignRequesterID()));

    // SignService
    //
    signRequestExtension.setSignService(DssUtils.toEntity(config.getSignServiceID()));

    // Requested signature algorithm
    //
    signRequestExtension.setRequestedSignatureAlgorithm(signRequestInput.getSignatureAlgorithm());

    // CertRequestProperties
    //
    if (signRequestInput.getAuthnRequirements().getAuthnContextClassRefs().size() > 1) {
      if (signRequestExtension.getVersion() != null && VERSION_1_4.compareTo(signRequestExtension.getVersion()) > 0) {
        log.info(
            "More that one AuthnContextClassRef URI is assigned to AuthnRequirements. Setting version of SignRequest to 1.4 ...");
        signRequestExtension.setVersion("1.4");
      }
    }
    signRequestExtension.setCertRequestProperties(DssUtils.toCertRequestProperties(
        signRequestInput.getCertificateRequirements(),
        signRequestInput.getAuthnRequirements().getAuthnContextClassRefs()));

    // SignMessage
    //
    if (signRequestInput.getSignMessageParameters() != null) {
      if (this.signMessageProcessor == null) {
        final String msg =
            "No signMessageProcessor has been configured - Cannot process request holding SignMessageParameters";
        log.error(msg);
        throw new InternalSignServiceIntegrationException(new ErrorCode.Code("config"), msg);
      }
      signRequestExtension
          .setSignMessage(this.signMessageProcessor.create(signRequestInput.getSignMessageParameters(), config));
    }

    // Install the sign request extension ...
    //
    signRequest.setSignRequestExtension(signRequestExtension);

    // Invoke all TBS processors ...
    //
    final SignTasks signTasks = dssExtObjectFactory.createSignTasks();
    for (final TbsDocument doc : signRequestInput.getTbsDocuments()) {
      final TbsDocumentProcessor<?> processor = this.tbsDocumentProcessors.stream()
          .filter(p -> p.supports(doc))
          .findFirst()
          .orElseThrow(() -> new InternalSignServiceIntegrationException(new ErrorCode.Code("config"),
              "Could not find document processor"));

      final Object cachedDocument = doc.getExtension() != null && doc.getExtension() instanceof DocumentExtension
          ? ((DocumentExtension) doc.getExtension()).getDocument()
          : null;
      if (cachedDocument != null) {
        // Clean up cached object. We don't want to save it to the session ...
        if (doc.getExtension().isEmpty()) {
          doc.setExtension(null);
        }
        else {
          doc.setExtension(new Extension(doc.getExtension()));
        }
      }

      final SignTaskData signTaskData =
          processor.process(new ProcessedTbsDocument(doc, cachedDocument), signRequestInput
              .getSignatureAlgorithm(), config);
      signTasks.getSignTaskDatas().add(signTaskData);
    }

    // Install the documents ...
    //
    signRequest.setSignTasks(signTasks);

    // Sign the document ...
    //
    final Document signedSignRequest =
        this.signSignRequest(signRequest, signRequestInput.getCorrelationId(), config.getSigningCredential());

    if (log.isTraceEnabled()) {
      log.trace("{}: Created SignRequest: {}", signRequestInput.getCorrelationId(),
          DOMUtils.prettyPrint(signedSignRequest));
    }

    // Transform and Base64-encode the message.
    //
    return new SignRequestProcessingResult(signRequest, DOMUtils.nodeToBase64(signedSignRequest));
  }

  /**
   * Signs the supplied {@code SignRequest} message.
   *
   * @param signRequest the SignRequest message to sign
   * @param correlationID the correlation ID for this operation
   * @param signingCredential the signing credential to use
   * @return a signed document
   * @throws InternalSignServiceIntegrationException for signature errors
   */
  protected Document signSignRequest(
      final SignRequestWrapper signRequest, final String correlationID, final PkiCredential signingCredential)
      throws InternalSignServiceIntegrationException {

    log.debug("{}: Signing SignRequest '{}' ...", correlationID, signRequest.getRequestID());

    try {
      // First marshall the JAXB to a DOM document ...
      //
      final Document signRequestDocument = JAXBMarshaller.marshall(signRequest.getWrappedSignRequest());

      log.debug("Signing: {}", DOMUtils.prettyPrint(signRequestDocument));

      // Get a signer and sign the message ...
      //
      final DefaultXMLSigner signer = new DefaultXMLSigner(signingCredential);
      signer.setSignatureLocation(this.xmlSignatureLocation);
      signer.setXPathTransform(null);
      final XMLSignerResult signerResult = signer.sign(signRequestDocument);
      log.debug("{}: SignRequest '{}' successfully signed", correlationID, signRequest.getRequestID());

      return signerResult.getSignedDocument();
    }
    catch (final JAXBException | SignatureException e) {
      log.error("{}: Error during signing of SignRequest - {}", correlationID, e.getMessage(), e);
      throw new InternalSignServiceIntegrationException(new ErrorCode.Code("signing"),
          "Error during signing of SignRequest", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<TbsDocumentProcessor<?>> getTbsDocumentProcessors() {
    return Collections.unmodifiableList(this.tbsDocumentProcessors);
  }

  /**
   * Sets the list of TBS document processors.
   *
   * @param tbsDocumentProcessors the document processors
   */
  public void setTbsDocumentProcessors(final List<TbsDocumentProcessor<?>> tbsDocumentProcessors) {
    this.tbsDocumentProcessors = tbsDocumentProcessors;
  }

  /**
   * Assigns the sign message processor to use.
   *
   * @param signMessageProcessor the sign message processor
   */
  public void setSignMessageProcessor(final SignMessageProcessor signMessageProcessor) {
    this.signMessageProcessor = signMessageProcessor;
  }

  /**
   * Assigns the document cache to use.
   *
   * @param documentCache the document cache
   */
  public void setDocumentCache(final DocumentCache documentCache) {
    this.documentCache = documentCache;
  }

  /**
   * Assigns the default version to use. If not set, section 3.1 of "DSS Extension for Federated Central Signing
   * Services" states that version 1.1 is the default. So, if the {@code defaultVersion} is not set, we don't include
   * the version unless a feature that requires a higher version is used.
   *
   * @param defaultVersion the version to default to
   */
  public void setDefaultVersion(final String defaultVersion) {
    if (defaultVersion != null) {
      this.defaultVersion = new ProtocolVersion(defaultVersion);
    }
  }

  /**
   * Returns the current time in XML time format.
   *
   * @return the current time
   */
  protected static XMLGregorianCalendar getNow() {
    try {
      final GregorianCalendar gregorianCalendar = new GregorianCalendar();
      final DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
      return datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
    }
    catch (final DatatypeConfigurationException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Ensures that all required properties have been assigned.
   *
   * <p>
   * Note: If executing in a Spring Framework environment this method is automatically invoked after all properties have
   * been assigned. Otherwise it should be explicitly invoked.
   * </p>
   *
   * @throws Exception if not all settings are correct
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    AssertThat.isNotEmpty(this.tbsDocumentProcessors, "At least one TBS document processor must be configured");
    if (this.signMessageProcessor == null) {
      log.warn("No signMessageProcessor assigned - Processor will not be able to process the SignMessage extension");
    }
  }

  /**
   * We extend the {@link Extension} class so that we can save a non-string object as an extension during the
   * processing.
   */
  private static class DocumentExtension extends Extension {

    @Serial
    private static final long serialVersionUID = -7525964206819771980L;

    /** The non-string document object that is stored. */
    @JsonIgnore
    @Getter
    @Setter
    private Object document;

    /**
     * Default constructor.
     */
    public DocumentExtension() {
      super();
    }

    /**
     * Copy constructor.
     *
     * @param extension the extension to initialize the object with
     */
    public DocumentExtension(final Extension extension) {
      super(extension);
    }

  }

}
