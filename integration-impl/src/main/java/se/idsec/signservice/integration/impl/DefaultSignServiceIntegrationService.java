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
package se.idsec.signservice.integration.impl;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestData;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.cache.IntegrationServiceCache;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.config.PolicyNotFoundException;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.process.SignRequestProcessor;
import se.swedenconnect.schemas.dss_1_0.SignRequest;

/**
 * Implementation of the SignService Integration Service.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultSignServiceIntegrationService implements SignServiceIntegrationService, InitializingBean {

  /** The version of this service. */
  private String version;

  /** The policies that this service supports. */
  private Map<String, IntegrationServiceConfiguration> policies;

  /** The session cache for the service. */
  private IntegrationServiceCache cache;

  /** The sign request processor. */
  private SignRequestProcessor signRequestProcessor;

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
      final IntegrationServiceConfiguration config = this.getConfigurationInternal(signRequestInput.getPolicy());

      // Validate the input to make sure that we can process it. Also assign default values to use as input.
      //
      final SignRequestInput input = this.signRequestProcessor.preProcess(signRequestInput, config);
      log.trace("{}: After validation and pre-processing the following input will be processed: {}", input.getCorrelationId(), input);

      // Create the SignRequest ...
      //
      final SignRequest signRequest = this.signRequestProcessor.process(input, config);

      return null;
    }
    finally {
      CorrelationID.clear();
    }
  }

  @Override
  public SignatureResult processSignResponse(final String signResponse, final String relayState, final SignatureState state,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {
    // TODO Auto-generated method stub
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public IntegrationServiceDefaultConfiguration getConfiguration(String policy) throws PolicyNotFoundException {
    DefaultSignServiceIntegrationService.log.debug("Request for policy '{}'",
      policy != null ? policy : IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME);

    final IntegrationServiceDefaultConfiguration publicConfig = this.getConfigurationInternal(policy).getPublicConfiguration();
    DefaultSignServiceIntegrationService.log.debug("Returning configuration for policy '{}': {}", publicConfig.getPolicy(), publicConfig);
    return publicConfig;
  }

  /**
   * Gets the actual policy to work with.
   * 
   * @param policy
   *          the policy name (null maps to the default policy)
   * @return the policy configuration
   * @throws PolicyNotFoundException
   *           if the policy is not found
   */
  private IntegrationServiceConfiguration getConfigurationInternal(final String policy) throws PolicyNotFoundException {
    final String _policy = policy != null ? policy : IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME;
    final IntegrationServiceConfiguration config = this.policies.get(_policy);
    if (config == null) {
      final String msg = String.format("Policy '%s' does not exist", _policy);
      DefaultSignServiceIntegrationService.log.info("{}", msg);
      throw new PolicyNotFoundException(msg);
    }
    return config;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getPolicies() {
    return this.policies.entrySet().stream().map(m -> m.getKey()).collect(Collectors.toList());
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
   * Sets the policies (with configuration) that this service implements/supports.
   *
   * @param policies
   *          a map of per policy configuration objects
   */
  public void setPolicies(final Map<String, IntegrationServiceConfiguration> policies) {
    this.policies = policies;
  }

  /**
   * Sets the integration session cache.
   * 
   * @param cache
   *          the session cache
   */
  public void setCache(final IntegrationServiceCache cache) {
    this.cache = cache;
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasText(this.version, "The property 'version' must be assigned");
    Assert.notEmpty(this.policies, "At least one policy must be configured");
    Assert.isTrue(this.policies.containsKey(IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME),
      "There must be a policy named 'default'");
    Assert.notNull(this.cache, "The property 'cache' must be assigned");
    Assert.notNull(this.signRequestProcessor, "The property 'signRequestProcessor' must be assigned");
  }

}
