/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.impl;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.ExtendedSignServiceIntegrationService;
import se.idsec.signservice.integration.SignRequestData;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.config.PolicyNotFoundException;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.BadRequestException;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.error.impl.InternalSignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePageFullException;
import se.idsec.signservice.integration.document.pdf.PdfSignaturePagePreferences;
import se.idsec.signservice.integration.document.pdf.PreparedPdfDocument;
import se.idsec.signservice.integration.process.SignRequestProcessingResult;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.idsec.signservice.integration.process.SignResponseProcessor;
import se.idsec.signservice.integration.state.SignatureSessionState;
import se.idsec.signservice.integration.state.SignatureStateProcessor;
import se.idsec.signservice.utils.AssertThat;

/**
 * Implementation of the SignService Integration Service.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignServiceIntegrationService implements ExtendedSignServiceIntegrationService {

  /** The default version. */
  public static final String VERSION = "1.3.0";

  /** The version of this service. Defaults to {@value #VERSION}. */
  private String version;

  /** Handles policy configurations. */
  private ConfigurationManager configurationManager;

  /** Processor for signature states. */
  private SignatureStateProcessor signatureStateProcessor;

  /** The sign request processor. */
  private SignRequestProcessor signRequestProcessor;

  /** The sign response processor. */
  private SignResponseProcessor signResponseProcessor;

  /**
   * Optional implementation of
   * {@link ExtendedSignServiceIntegrationService#preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}.
   */
  private PdfSignaturePagePreparator pdfSignaturePagePreparator;

  /**
   * Default constructor.
   */
  public DefaultSignServiceIntegrationService() {
  }

  /** {@inheritDoc} */
  @Override
  public SignRequestData createSignRequest(final SignRequestInput signRequestInput) throws SignServiceIntegrationException {

    CorrelationID.init(signRequestInput != null ? signRequestInput.getCorrelationId() : null);
    log.debug("{}: Request for creating a SignRequest: {}", CorrelationID.id(), signRequestInput);

    try {
      // Find out under which policy we should create the SignRequest.
      //
      final IntegrationServiceConfiguration config = this.configurationManager.getConfiguration(signRequestInput.getPolicy());
      if (config == null) {
        final String msg = String.format("Policy '%s' does not exist", signRequestInput.getPolicy());
        log.info("{}", msg);
        throw new PolicyNotFoundException(msg);
      }

      // Validate the input to make sure that we can process it. Also assign default values to use as input.
      //
      final SignRequestInput input = this.signRequestProcessor.preProcess(signRequestInput, config);
      log.trace("{}: After validation and pre-processing the following input will be processed: {}", input.getCorrelationId(), input);

      // Create the SignRequest ...
      //
      // Generate an ID for this request.
      //
      final String requestID = UUID.randomUUID().toString();
      log.info("{}: Generated SignRequest RequestID attribute: {}", input.getCorrelationId(), requestID);

      final SignRequestProcessingResult processingResult = this.signRequestProcessor.process(input, requestID, config);

      // Setup the signature state ...
      //
      final SignatureState state = this.signatureStateProcessor.createSignatureState(input, processingResult.getSignRequest(), config
        .isStateless());

      // And finally build the result structure that the caller may use to build the POST form
      // that takes the user to the signature service.
      //
      final SignRequestData signRequestData = SignRequestData.builder()
        .state(state)
        .signRequest(processingResult.getEncodedSignRequest())
        .relayState(requestID)
        .destinationUrl(input.getDestinationUrl())
        .build();

      return signRequestData;
    }
    finally {
      CorrelationID.clear();
    }
  }

  /** {@inheritDoc} */
  @Override
  public SignatureResult processSignResponse(final String signResponse, final String relayState, final SignatureState state,
      final SignResponseProcessingParameters parameters)
      throws SignResponseCancelStatusException, SignResponseErrorStatusException, SignServiceIntegrationException {

    log.debug("Request to process SignResponse for ID '{}'", relayState);

    // Get hold of the session state ...
    //
    final SignatureSessionState sessionState = this.signatureStateProcessor.getSignatureState(
      state, parameters != null ? parameters.getExtensionValue(OWNER_ID_EXTENSION_KEY) : null);

    CorrelationID.init(sessionState.getCorrelationId());

    // Sanity check to make sure that the relayState and signature state corresponds ...
    //
    if (!Objects.equals(relayState, state.getId())) {
      final String msg = String.format("Bad request - relayState (%s) does not correspond to signature state (%s)",
        relayState, state.getId());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new BadRequestException(new ErrorCode.Code("session"), msg);
    }

    // Get the policy configuration for this operation ...
    //
    final IntegrationServiceConfiguration config = this.configurationManager.getConfiguration(sessionState.getPolicy());
    if (config == null) {
      final String msg = String.format("Internal error - policy '%s' is not available", sessionState.getPolicy());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new InternalSignServiceIntegrationException(new ErrorCode.Code("config"), msg);
    }

    // Invoke the processor ...
    //
    return this.signResponseProcessor.processSignResponse(signResponse, sessionState, config, parameters);
  }

  /** {@inheritDoc} */
  @Override
  public PreparedPdfDocument preparePdfSignaturePage(final String policy, final byte[] pdfDocument,
      final PdfSignaturePagePreferences signaturePagePreferences)
      throws InputValidationException, PdfSignaturePageFullException, SignServiceIntegrationException {

    if (this.pdfSignaturePagePreparator != null) {
      final String _policy = policy != null ? policy : this.configurationManager.getDefaultPolicyName();
      final IntegrationServiceConfiguration config = this.configurationManager.getConfiguration(_policy);
      if (config == null) {
        final String msg = String.format("Policy '%s' does not exist", _policy);
        log.info("{}", msg);
        throw new PolicyNotFoundException(msg);
      }
      return this.pdfSignaturePagePreparator.preparePdfSignaturePage(pdfDocument, signaturePagePreferences, config);
    }
    else {
      throw new IllegalArgumentException("No PdfSignaturePagePreparator installed - can not excecute method");
    }
  }

  /** {@inheritDoc} */
  @Override
  public IntegrationServiceDefaultConfiguration getConfiguration(final String policy) throws PolicyNotFoundException {
    final String _policy = policy != null ? policy : this.configurationManager.getDefaultPolicyName();
    log.debug("Request for policy '{}'", _policy);

    final IntegrationServiceConfiguration config = this.configurationManager.getConfiguration(_policy);
    if (config == null) {
      final String msg = String.format("Policy '%s' does not exist", _policy);
      log.info("{}", msg);
      throw new PolicyNotFoundException(msg);
    }
    final IntegrationServiceDefaultConfiguration publicConfig = config.getPublicConfiguration();
    log.debug("Returning configuration for policy '{}': {}", publicConfig.getPolicy(), publicConfig);
    return publicConfig;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getPolicies() {
    return this.configurationManager.getPolicies();
  }

  /**
   * Assigns the policy configuration manager bean.
   *
   * @param configurationManager
   *          the policy configuration manager
   */
  public void setConfigurationManager(final ConfigurationManager configurationManager) {
    this.configurationManager = configurationManager;
  }

  /** {@inheritDoc} */
  @Override
  public String getVersion() {
    return this.version;
  }

  /**
   * Assigns the version string.
   *
   * @param version
   *          the version
   */
  public void setVersion(final String version) {
    this.version = version;
  }

  /**
   * Assigns the signature state processor.
   *
   * @param signatureStateProcessor
   *          the processor
   */
  public void setSignatureStateProcessor(final SignatureStateProcessor signatureStateProcessor) {
    this.signatureStateProcessor = signatureStateProcessor;
  }

  /**
   * Sets the sign request processor.
   *
   * @param signRequestProcessor
   *          the sign request processor
   */
  public void setSignRequestProcessor(final SignRequestProcessor signRequestProcessor) {
    this.signRequestProcessor = signRequestProcessor;
  }

  /**
   * Sets the sign response processor.
   *
   * @param signResponseProcessor
   *          the sign response processor
   */
  public void setSignResponseProcessor(final SignResponseProcessor signResponseProcessor) {
    this.signResponseProcessor = signResponseProcessor;
  }

  /**
   * Assigns the implementation for {@link #preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}.
   *
   * @param pdfSignaturePagePreparator
   *          the implementation for {@link #preparePdfSignaturePage(String, byte[], PdfSignaturePagePreferences)}
   */
  public void setPdfSignaturePagePreparator(final PdfSignaturePagePreparator pdfSignaturePagePreparator) {
    this.pdfSignaturePagePreparator = pdfSignaturePagePreparator;
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
    if (StringUtils.isBlank(this.version)) {
      this.version = VERSION;
    }
    AssertThat.isNotNull(this.configurationManager, "The 'configurationManager' must be assigned");
    AssertThat.isNotNull(this.signatureStateProcessor, "The property 'signatureStateProcessor' must be assigned");
    AssertThat.isNotNull(this.signRequestProcessor, "The property 'signRequestProcessor' must be assigned");
    AssertThat.isNotNull(this.signResponseProcessor, "The property 'signResponseProcessor' must be assigned");
  }

}
