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
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignMessageMimeType;
import se.idsec.signservice.integration.SignMessageParameters;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.authentication.AuthnRequirements;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.BadRequestException;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;
import se.idsec.signservice.integration.process.SignRequestProcessor;
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

  /** {@inheritDoc} */
  @Override
  public SignRequestInput preProcess(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config)
      throws BadRequestException {

    // Get ID for logging ...
    final String id = StringUtils.hasText(signRequestInput.getCorrelationId())
        ? signRequestInput.getCorrelationId()
        : UUID.randomUUID().toString();

    // TODO: Set correlationID to TLS

    // First validate ...
    //
    this.signRequestInputValidator.validateObject(signRequestInput, "signRequestInput", config, id);

    // The apply default values ...
    //
    SignRequestInput.SignRequestInputBuilder inputBuilder = signRequestInput.toBuilder();

    if (!StringUtils.hasText(signRequestInput.getCorrelationId())) {
      log.debug("No correlation ID provided in SignRequestInput, using '{}'", id);
      inputBuilder.correlationId(id);
    }

    // Policy
    if (signRequestInput.getPolicy() == null) {
      log.debug("{}: No policy given in input, using '{}'", id, config.getPolicy());
      inputBuilder.policy(config.getPolicy());
    }

    // SignRequesterID
    if (signRequestInput.getSignRequesterID() == null) {
      log.debug("{}: No signRequesterID given in input, using '{}'", id, config.getDefaultSignRequesterID());
      inputBuilder.signRequesterID(config.getDefaultSignRequesterID());
    }

    // ReturnUrl
    if (signRequestInput.getReturnUrl() == null) {
      log.debug("{}: No returnUrl given in input, using '{}'", id, config.getDefaultReturnUrl());
      inputBuilder.returnUrl(config.getDefaultReturnUrl());
    }

    // DestinationUrl
    if (signRequestInput.getDestinationUrl() == null) {
      log.debug("{}: No destinationUrl given in input, using '{}'", id, config.getDefaultDestinationUrl());
      inputBuilder.destinationUrl(config.getDefaultDestinationUrl());
    }

    // SignatureAlgorithm
    if (signRequestInput.getSignatureAlgorithm() == null) {
      log.debug("{}: No signatureAlgorithm given in input, using '{}'", id, config.getDefaultSignatureAlgorithm());
      inputBuilder.signatureAlgorithm(config.getDefaultSignatureAlgorithm());
    }

    // AuthnRequirements
    //
    AuthnRequirements authnRequirements = signRequestInput.getAuthnRequirements() != null
        ? signRequestInput.getAuthnRequirements().toBuilder().build()
        : new AuthnRequirements();

    String authnServiceID = authnRequirements.getAuthnServiceID();
    if (authnServiceID == null) {
      log.debug("{}: No authnRequirements.authnServiceID given in input, using '{}'", id, config.getDefaultAuthnServiceID());
      authnRequirements.setAuthnServiceID(config.getDefaultAuthnServiceID());
      authnServiceID = config.getDefaultAuthnServiceID();
    }
    if (authnRequirements.getAuthnContextRef() == null) {
      log.debug("{}: No authnRequirements.authnContextRef given in input, using '{}'", id, config.getDefaultAuthnContextRef());
      authnRequirements.setAuthnContextRef(config.getDefaultAuthnContextRef());
    }
    if (authnRequirements.getRequestedSignerAttributes() == null || authnRequirements.getRequestedSignerAttributes().isEmpty()) {
      log.info("{}: No requested signer attributes specified - \"anonymous signature\"", id);
    }
    inputBuilder.authnRequirements(authnRequirements);

    // SigningCertificateRequirements
    //
    if (signRequestInput.getCertificateRequirements() == null) {
      log.debug("{}: No certificateRequirements given in input, using {}", id, config.getDefaultCertificateRequirements());
      inputBuilder.certificateRequirements(config.getDefaultCertificateRequirements());
    }

    // TbsDocuments
    if (signRequestInput.getTbsDocuments() == null || signRequestInput.getTbsDocuments().isEmpty()) {
      log.warn("{}: No documents available in input", id);
      throw new BadRequestException(new ErrorCode.Code("missing-tbs-document"), "Missing tbsDocuments");
    }

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
      inputBuilder.tbsDocument(processor.preProcess(id, doc, config, fieldName));
    }

    // SignMessageParameters
    //
    if (signRequestInput.getSignMessageParameters() != null) {
      SignMessageParameters.SignMessageParametersBuilder smpBuilder = null;
      if (signRequestInput.getSignMessageParameters().getMimeType() == null) {
        log.debug("{}: No signMessageParameters.mimeType given in input, using {}", id, SignMessageMimeType.TEXT.getMimeType());
        smpBuilder = signRequestInput.getSignMessageParameters().toBuilder();
        smpBuilder.mimeType(SignMessageMimeType.TEXT);
      }
      if (signRequestInput.getSignMessageParameters().getMustShow() == null) {
        log.debug("{}: signMessageParameters.mustShow not set, defaulting to false", id);
        if (smpBuilder == null) {
          smpBuilder = signRequestInput.getSignMessageParameters().toBuilder();
        }
        smpBuilder.mustShow(false);
      }
      if (signRequestInput.getSignMessageParameters().isPerformEncryption()
          && signRequestInput.getSignMessageParameters().getDisplayEntity() == null) {
        log.debug("{}: signMessageParameters.displayEntity is not set in input, defaulting to {}", id, authnServiceID);
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

  @Override
  public SignRequest process(SignRequestInput signRequestInput, IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {

    // Generate an ID for this request.
    final String requestID = UUID.randomUUID().toString();

    return null;
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notEmpty(this.tbsDocumentProcessors, "At least one TBS document processor must be installed");
  }

}
