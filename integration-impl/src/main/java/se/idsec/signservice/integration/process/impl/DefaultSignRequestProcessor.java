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

import java.security.SignatureException;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.w3c.dom.Document;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
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
import se.idsec.signservice.security.sign.SigningCredential;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation.ChildPosition;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.utils.AssertThat;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.JAXBMarshaller;
import se.litsec.swedisheid.opensaml.saml2.authentication.LevelofAssuranceAuthenticationContextURI;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;

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

  /** The processor for SignMessages. */
  private SignMessageProcessor signMessageProcessor;

  /** Object factory for DSS objects. */
  private static se.swedenconnect.schemas.dss_1_0.ObjectFactory dssObjectFactory = new se.swedenconnect.schemas.dss_1_0.ObjectFactory();

  /** Object factory for DSS-Ext objects. */
  private static se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtObjectFactory = new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();

  /** Needed when signing the sign request. */
  private XMLSignatureLocation xmlSignatureLocation;

  /**
   * Constructor.
   */
  public DefaultSignRequestProcessor() {
    try {
      this.xmlSignatureLocation = new XMLSignatureLocation("/*/*[local-name()='OptionalInputs']", ChildPosition.LAST);
    }
    catch (XPathExpressionException e) {
      log.error("Failed to setup XPath for signature inclusion", e);
      throw new SecurityException("Failed to setup XPath for signature inclusion", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestInput preProcess(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config)
      throws InputValidationException {

    // First validate ...
    //
    this.signRequestInputValidator.validateObject(signRequestInput, "signRequestInput", config);

    // Then apply default values ...
    //
    SignRequestInput.SignRequestInputBuilder inputBuilder = signRequestInput.toBuilder();

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
      log.debug("{}: No signRequesterID given in input, using '{}'", CorrelationID.id(), config.getDefaultSignRequesterID());
      inputBuilder.signRequesterID(config.getDefaultSignRequesterID());
    }

    // ReturnUrl
    if (signRequestInput.getReturnUrl() == null) {
      log.debug("{}: No returnUrl given in input, using '{}'", CorrelationID.id(), config.getDefaultReturnUrl());
      inputBuilder.returnUrl(config.getDefaultReturnUrl());
    }

    // DestinationUrl
    if (signRequestInput.getDestinationUrl() == null) {
      log.debug("{}: No destinationUrl given in input, using '{}'", CorrelationID.id(), config.getDefaultDestinationUrl());
      inputBuilder.destinationUrl(config.getDefaultDestinationUrl());
    }

    // SignatureAlgorithm
    if (signRequestInput.getSignatureAlgorithm() == null) {
      log.debug("{}: No signatureAlgorithm given in input, using '{}'", CorrelationID.id(), config.getDefaultSignatureAlgorithm());
      inputBuilder.signatureAlgorithm(config.getDefaultSignatureAlgorithm());
    }

    // AuthnRequirements
    //
    AuthnRequirements authnRequirements = signRequestInput.getAuthnRequirements() != null
        ? signRequestInput.getAuthnRequirements().toBuilder().build()
        : new AuthnRequirements();

    String authnServiceID = authnRequirements.getAuthnServiceID();
    if (authnServiceID == null) {
      log.debug("{}: No authnRequirements.authnServiceID given in input, using '{}'", CorrelationID.id(),
        config.getDefaultAuthnServiceID());
      authnRequirements.setAuthnServiceID(config.getDefaultAuthnServiceID());
      authnServiceID = config.getDefaultAuthnServiceID();
    }
    if (authnRequirements.getAuthnContextRef() == null) {
      log.debug("{}: No authnRequirements.authnContextRef given in input, using '{}'",
        CorrelationID.id(), config.getDefaultAuthnContextRef());
      authnRequirements.setAuthnContextRef(config.getDefaultAuthnContextRef());
    }
    if (authnRequirements.getRequestedSignerAttributes() == null || authnRequirements.getRequestedSignerAttributes().isEmpty()) {
      log.info("{}: No requested signer attributes specified - \"anonymous signature\"", CorrelationID.id());
    }
    inputBuilder.authnRequirements(authnRequirements);

    // SigningCertificateRequirements
    //
    if (signRequestInput.getCertificateRequirements() == null) {
      log.debug("{}: No certificateRequirements given in input, using {}", CorrelationID.id(), config.getDefaultCertificateRequirements());
      inputBuilder.certificateRequirements(config.getDefaultCertificateRequirements());
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

      final ProcessedTbsDocument processedTbsDocument = processor.preProcess(doc, config, fieldName);
      if (processedTbsDocument.getDocumentObject() != null) {
        if (processedTbsDocument.getDocumentObject() != null) {
          final Extension ext = processedTbsDocument.getTbsDocument().getExtension();
          final DocumentExtension docExt = ext == null ? new DocumentExtension() : new DocumentExtension(ext);
          docExt.setDocument(processedTbsDocument.getDocumentObject());
          processedTbsDocument.getTbsDocument().setExtension(docExt);
        }
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

    SignRequestInput processedSignRequestInput = inputBuilder.build();

    // Apply special handling (workarounds etc.)
    //
    processedSignRequestInput = this.applyPreProcessWorkarounds(processedSignRequestInput, config);

    return processedSignRequestInput;
  }

  /**
   * Work-arounds. Placed here so that it doesn't mess up the rest of the code.
   * 
   * @param input
   *          the sign request input to apply work-arounds on
   * @param config
   *          the configuration
   * @return a (possibly) updated sign request input object
   */
  private SignRequestInput applyPreProcessWorkarounds(final SignRequestInput input, final IntegrationServiceConfiguration config) {
    final SignRequestInput updatedInput = input;

    // To cover up for a bug i Cybercom's sign service. They expect to receive a sigmessage
    // URI in the request (which is wrong).
    //
    if (updatedInput.getSignMessageParameters() != null) {
      if (config.getExtension() != null && config.getExtension().get("send-sigmessage-uri") != null) {
        Boolean ccWorkaround = Boolean.parseBoolean(config.getExtension().get("send-sigmessage-uri"));
        if (ccWorkaround) {
          final String loa = updatedInput.getAuthnRequirements().getAuthnContextRef();
          LevelofAssuranceAuthenticationContextURI.LoaEnum loaEnum = LevelofAssuranceAuthenticationContextURI.LoaEnum.parse(loa);
          if (loaEnum != null) {
            LevelofAssuranceAuthenticationContextURI.LoaEnum updatedLoaEnum = LevelofAssuranceAuthenticationContextURI.LoaEnum
              .plusSigMessage(loaEnum);
            if (updatedLoaEnum != null) {
              log.info("{}: Applying workaround for Cybercom sigmessage URI bug. Changing AuthnContextRef from '{}' to '{}'",
                CorrelationID.id(), loa, updatedLoaEnum.getUri());
              updatedInput.getAuthnRequirements().setAuthnContextRef(updatedLoaEnum.getUri());
            }
          }
        }
      }
    }

    return updatedInput;
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestProcessingResult process(final SignRequestInput signRequestInput, final String requestID,
      final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {

    // Start building the SignRequest ...
    //
    final long now = System.currentTimeMillis();

    SignRequestWrapper signRequest = new SignRequestWrapper(dssObjectFactory.createSignRequest());
    signRequest.setProfile(DssUtils.DSS_PROFILE);
    signRequest.setRequestID(requestID);

    SignRequestExtension signRequestExtension = dssExtObjectFactory.createSignRequestExtension();

    // RequestTime
    //
    signRequestExtension.setRequestTime(getNow());

    // Conditions (use OpenSAML instead of JAXB)
    //
    Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
    final DateTime currentTime = new DateTime(now);
    conditions.setNotBefore(currentTime.minusMinutes(1));  // TODO: make configurable
    conditions.setNotOnOrAfter(currentTime.plusMinutes(5));

    AudienceRestriction audienceRestriction = (AudienceRestriction) XMLObjectSupport.buildXMLObject(
      AudienceRestriction.DEFAULT_ELEMENT_NAME);
    Audience audience = (Audience) XMLObjectSupport.buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
    audience.setAudienceURI(signRequestInput.getReturnUrl());
    audienceRestriction.getAudiences().add(audience);

    conditions.getAudienceRestrictions().add(audienceRestriction);

    signRequestExtension.setConditions(DssUtils.toJAXB(conditions, se.swedenconnect.schemas.saml_2_0.assertion.Conditions.class));

    // Signer
    //
    if (signRequestInput.getAuthnRequirements().getRequestedSignerAttributes() != null
        && !signRequestInput.getAuthnRequirements().getRequestedSignerAttributes().isEmpty()) {

      signRequestExtension.setSigner(DssUtils.toAttributeStatement(signRequestInput.getAuthnRequirements().getRequestedSignerAttributes()));
    }

    // IdentityProvider
    //
    signRequestExtension.setIdentityProvider(DssUtils.toEntity(signRequestInput.getAuthnRequirements().getAuthnServiceID()));

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
    signRequestExtension.setCertRequestProperties(DssUtils.toCertRequestProperties(
      signRequestInput.getCertificateRequirements(), signRequestInput.getAuthnRequirements().getAuthnContextRef()));

    // SignMessage
    //
    if (signRequestInput.getSignMessageParameters() != null) {
      signRequestExtension.setSignMessage(this.signMessageProcessor.create(signRequestInput.getSignMessageParameters(), config));
    }

    // Install the sign request extension ...
    //
    signRequest.setSignRequestExtension(signRequestExtension);

    // Invoke all TBS processors ...
    //
    SignTasks signTasks = dssExtObjectFactory.createSignTasks();
    for (final TbsDocument doc : signRequestInput.getTbsDocuments()) {
      final TbsDocumentProcessor<?> processor = this.tbsDocumentProcessors.stream()
        .filter(p -> p.supports(doc))
        .findFirst()
        .orElseThrow(() -> new InternalSignServiceIntegrationException(new ErrorCode.Code("config"), "Could not find document processor"));

      final Object cachedDocument = doc.getExtension() != null && DocumentExtension.class.isInstance(doc.getExtension())
          ? DocumentExtension.class.cast(doc.getExtension()).getDocument()
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

      final SignTaskData signTaskData = processor.process(new ProcessedTbsDocument(doc, cachedDocument), signRequestInput
        .getSignatureAlgorithm(), config);
      signTasks.getSignTaskDatas().add(signTaskData);
    }

    // Install the documents ...
    //
    signRequest.setSignTasks(signTasks);

    // Sign the document ...
    //
    Document signedSignRequest = this.signSignRequest(signRequest, signRequestInput.getCorrelationId(), config.getSigningCredential());

    if (log.isTraceEnabled()) {
      log.trace("{}: Created SignRequest: {}", signRequestInput.getCorrelationId(), DOMUtils.prettyPrint(signedSignRequest));
    }

    // Transform and Base64-encode the message.
    //
    return new SignRequestProcessingResult(signRequest, DOMUtils.nodeToBase64(signedSignRequest));
  }

  /**
   * Signs the supplied {@code SignRequest} message.
   * 
   * @param signRequest
   *          the SignRequest message to sign
   * @param correlationID
   *          the correlation ID for this operation
   * @param signingCredential
   *          the signing credential to use
   * @return a signed document
   * @throws InternalSignServiceIntegrationException
   *           for signature errors
   */
  protected Document signSignRequest(final SignRequestWrapper signRequest,
      final String correlationID, final SigningCredential signingCredential) throws InternalSignServiceIntegrationException {

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
      XMLSignerResult signerResult = signer.sign(signRequestDocument);
      log.debug("{}: SignRequest '{}' successfully signed", correlationID, signRequest.getRequestID());

      return signerResult.getSignedDocument();
    }
    catch (JAXBException | SignatureException e) {
      log.error("{}: Error during signing of SignRequest - {}", correlationID, e.getMessage(), e);
      throw new InternalSignServiceIntegrationException(new ErrorCode.Code("signing"), "Error during signing of SignRequest", e);
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
   * @param tbsDocumentProcessors
   *          the document processors
   */
  public void setTbsDocumentProcessors(List<TbsDocumentProcessor<?>> tbsDocumentProcessors) {
    this.tbsDocumentProcessors = tbsDocumentProcessors;
  }

  /**
   * Assigns the sign message processor to use.
   * 
   * @param signMessageProcessor
   *          the sign message processor
   */
  public void setSignMessageProcessor(SignMessageProcessor signMessageProcessor) {
    this.signMessageProcessor = signMessageProcessor;
  }

  /**
   * Returns the current time in XML time format.
   * 
   * @return the current time
   */
  protected static XMLGregorianCalendar getNow() {
    try {
      GregorianCalendar gregorianCalendar = new GregorianCalendar();
      DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
      XMLGregorianCalendar now = datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
      return now;
    }
    catch (DatatypeConfigurationException e) {
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
   * @throws Exception
   *           if not all settings are correct
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    AssertThat.isNotEmpty(this.tbsDocumentProcessors, "At least one TBS document processor must be configured");
    AssertThat.isNotNull(this.signMessageProcessor, "Missing 'signMessageProcessor'");
  }

  /**
   * We extend the {@link Extension} class so that we can save a non-string object as an extension during the
   * processing.
   */
  private static class DocumentExtension extends Extension {

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
     * @param m
     *          the map to initialize the object with
     */
    public DocumentExtension(final Extension extension) {
      super(extension);
    }

  }

}
