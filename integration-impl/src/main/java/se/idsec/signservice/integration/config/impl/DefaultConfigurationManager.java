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
package se.idsec.signservice.integration.config.impl;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default implementation of the {@link ConfigurationManager} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultConfigurationManager implements ConfigurationManager {

  /** The policies that this service supports. */
  private final Map<String, ? extends IntegrationServiceConfiguration> policies;

  /** The default policy name. */
  private String defaultPolicyName;

  /**
   * Constructor.
   *
   * @param policies a mapping between policy names and service configuration objects
   * @throws IllegalArgumentException if policies are invalid
   */
  public DefaultConfigurationManager(final Map<String, ? extends IntegrationServiceConfiguration> policies)
      throws IllegalArgumentException {
    this.policies = policies;
    if (this.policies.isEmpty()) {
      throw new IllegalArgumentException("At least one policy must be configured");
    }

    // We have the policy name in two places, both as the key and the named property. Make sure that
    // they are correct (and also set the property if missing).
    //
    for (final Map.Entry<String, ? extends IntegrationServiceConfiguration> p : this.policies.entrySet()) {
      if (StringUtils.isNotBlank(p.getValue().getPolicy()) && !p.getKey().equals(p.getValue().getPolicy().trim())) {
        throw new IllegalArgumentException(String.format("Illegal policyName (%s) - expected '%s'",
            p.getValue().getPolicy(), p.getKey()));
      }
      else if (StringUtils.isBlank(p.getValue().getPolicy())) {
        if (p.getValue() instanceof DefaultIntegrationServiceConfiguration) {
          ((DefaultIntegrationServiceConfiguration) p.getValue()).setPolicy(p.getKey());
        }
      }
    }

    // Go through all policies and make sure that are complete.
    //
    if (this.policies.size() > 1) {
      for (final IntegrationServiceConfiguration policy : this.policies.values()) {
        this.mergePolicies(policy, new ArrayList<>());
      }
    }

    // Validate all policies
    //
    final IntegrationServiceConfigurationValidator validator = new IntegrationServiceConfigurationValidator();
    for (final Map.Entry<String, ? extends IntegrationServiceConfiguration> p : this.policies.entrySet()) {
      log.debug("Validating policy '{}' ...", p.getKey());
      try {
        validator.validateObject(p.getValue(), "serviceConfiguration[" + p.getKey() + "]", null);
        log.debug("Policy '{}' was successfully validated", p.getKey());
      }
      catch (final InputValidationException e) {
        throw new IllegalArgumentException("Service configuration " + p.getKey() + " is invalid", e);
      }
    }
  }

  private void mergePolicies(final IntegrationServiceConfiguration policy, final List<String> policiesForMerge) {
    final String parentPolicy = policy.getParentPolicy();
    if (StringUtils.isBlank(parentPolicy)) {
      return;
    }
    final IntegrationServiceConfiguration parent = this.policies.get(parentPolicy);
    if (parent == null) {
      throw new IllegalArgumentException(
          String.format("Policy '%s' states parentPolicy '%s' - This policy can not be found", policy.getPolicy(),
              parentPolicy));
    }
    if (StringUtils.isNotEmpty(parent.getParentPolicy())) {
      // Oops, the parent policy also has a parent. First check so that we don't have a circular dependency.
      //
      if (policiesForMerge.contains(parentPolicy)) {
        throw new IllegalArgumentException(String.format("Circular parent policy for policy '%s'", policy.getPolicy()));
      }
      policiesForMerge.add(policy.getPolicy());
      this.mergePolicies(parent, policiesForMerge);
    }
    else {
      policy.mergeConfiguration(parent);
    }
  }

  /** {@inheritDoc} */
  @Override
  public IntegrationServiceConfiguration getConfiguration(final String policy) {
    return this.policies.get(policy != null ? policy : this.getDefaultPolicyName());
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<String> getPolicies() {
    return new ArrayList<>(this.policies.keySet());
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public String getDefaultPolicyName() {
    return this.defaultPolicyName != null
        ? this.defaultPolicyName
        : IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME;
  }

  /** {@inheritDoc} */
  @Override
  public void setDefaultPolicyName(@Nonnull final String defaultPolicyName) {
    this.defaultPolicyName = defaultPolicyName;
  }

  /**
   * Checks that the settings for this object is valid.
   *
   * @throws Exception for initialization errors
   */
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    if (!this.policies.containsKey(this.getDefaultPolicyName())) {
      throw new IllegalArgumentException(
          String.format("There must be a policy named '%s'", this.getDefaultPolicyName()));
    }
  }

}
