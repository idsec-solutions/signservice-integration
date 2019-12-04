/*
 * Copyright 2019 IDsec Solutions AB
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

import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.joda.time.DateTime;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.idsec.signservice.integration.signmessage.SignMessageMimeType;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;
import se.idsec.signservice.integration.signmessage.SignMessageProcessor;
import se.swedenconnect.schemas.csig.dssext_1_1.SignRequestExtension;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTasks;
import se.swedenconnect.schemas.dss_1_0.AnyType;
import se.swedenconnect.schemas.dss_1_0.InputDocuments;
import se.swedenconnect.schemas.dss_1_0.SignRequest;

/**
 * Default implementation of the {@link SignRequestProcessor} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignRequestProcessor implements SignRequestProcessor, InitializingBean {

  /** Processors for different TBS documents. */
  private List<TbsDocumentProcessor> tbsDocumentProcessors;

  /** Validator. */
  private final SignRequestInputValidator signRequestInputValidator = new SignRequestInputValidator();
  
  /** The processor for SignMessages. */
  private SignMessageProcessor signMessageProcessor;

  /** {@inheritDoc} */
  @Override
  public SignRequestInput preProcess(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config)
      throws InputValidationException {

    // First validate ...
    //
    this.signRequestInputValidator.validateObject(signRequestInput, "signRequestInput", config);

    // The apply default values ...
    //
    SignRequestInput.SignRequestInputBuilder inputBuilder = signRequestInput.toBuilder();

    if (!StringUtils.hasText(signRequestInput.getCorrelationId())) {
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
      final TbsDocumentProcessor processor = this.tbsDocumentProcessors.stream()
        .filter(p -> p.supports(doc))
        .findFirst()
        .orElseThrow(() -> new InputValidationException(fieldName,
          String.format("Document of type '%s' is not supported", doc.getMimeType())));
      inputBuilder.tbsDocument(processor.preProcess(doc, config, fieldName));
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
  public SignRequest process(SignRequestInput signRequestInput, IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {

    // Generate an ID for this request.
    final String requestID = UUID.randomUUID().toString();
    log.info("{}: Generated SignRequest RequestID attribute: {}", signRequestInput.getCorrelationId(), requestID);

    // Start building the SignRequest ...
    //
    final long now = System.currentTimeMillis();

    SignRequest signRequest = new SignRequest();
    signRequest.setProfile("http://id.elegnamnden.se/csig/1.1/dss-ext/profile");  // TODO: use constant
    signRequest.setRequestID(requestID);

    SignRequestExtension signRequestExtension = new SignRequestExtension();

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
    audience.setAudienceURI(signRequestInput.getDestinationUrl());
    audienceRestriction.getAudiences().add(audience);

    conditions.getAudienceRestrictions().add(audienceRestriction);

    signRequestExtension.setConditions(DssUtils.toJAXB(conditions, se.swedenconnect.schemas.saml_2_0.assertion.Conditions.class));

    // Signer
    //
    if (signRequestInput.getAuthnRequirements().getRequestedSignerAttributes() != null
        && !signRequestInput.getAuthnRequirements().getRequestedSignerAttributes().isEmpty()) {

      signRequestExtension.setSigner(DssUtils.toSigner(signRequestInput.getAuthnRequirements().getRequestedSignerAttributes()));
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

    // CertRequestProperties
    //
    signRequestExtension.setCertRequestProperties(DssUtils.toCertRequestProperties(
      signRequestInput.getCertificateRequirements(), signRequestInput.getAuthnRequirements().getAuthnContextRef()));

    // SignMessage
    //
    signRequestExtension.setSignMessage(this.signMessageProcessor.create(signRequestInput.getSignMessageParameters(), config));

    // Install the sign request extension ...
    //
    AnyType optionalInputs = new AnyType();
    optionalInputs.getAnies().add(DssUtils.toElement(signRequestExtension));
    signRequest.setOptionalInputs(optionalInputs);
    
    // Invoke all TBS processors ...
    //
    SignTasks signTasks = new SignTasks();
    for (final TbsDocument doc : signRequestInput.getTbsDocuments()) {
      final TbsDocumentProcessor processor = this.tbsDocumentProcessors.stream()
          .filter(p -> p.supports(doc))
          .findFirst()
          .orElseThrow(() -> new InternalSignServiceIntegrationException(new ErrorCode.Code("config"), "Could not find document processor"));
      
      final SignTaskData signTaskData = processor.process(doc, config);
      signTasks.getSignTaskDatas().add(signTaskData);
    }
    
    // Install the documents ...
    //
    InputDocuments inputDocuments = new InputDocuments();
    AnyType dssOther = new AnyType();
    dssOther.getAnies().add(DssUtils.toElement(signTasks));
    inputDocuments.getDocumentsAndTransformedDatasAndDocumentHashes().add(dssOther);
    
    // Finally, sign the document ...
    //
    
    // TODO

    return signRequest;
  }

  /** {@inheritDoc} */
  @Override
  public List<TbsDocumentProcessor> getTbsDocumentProcessors() {
    return Collections.unmodifiableList(this.tbsDocumentProcessors);
  }

  /**
   * Sets the list of TBS document processors.
   * 
   * @param tbsDocumentProcessors
   *          the document processors
   */
  public void setTbsDocumentProcessors(List<TbsDocumentProcessor> tbsDocumentProcessors) {
    this.tbsDocumentProcessors = tbsDocumentProcessors;
  }
  
  /**
   * Assigns the sign message processor to use.
   * @param signMessageProcessor the sign message processor
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notEmpty(this.tbsDocumentProcessors, "At least one TBS document processor must be configured");
    Assert.notNull(this.signMessageProcessor, "Missing 'signMessageProcessor'");
  }

}
