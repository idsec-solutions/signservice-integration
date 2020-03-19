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
package se.idsec.signservice.integration.config.impl;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import se.idsec.signservice.integration.config.ConfigurationManager;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.IntegrationServiceDefaultConfiguration;

/**
 * Default implementation of the {@link ConfigurationManager} interface.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultConfigurationManager implements ConfigurationManager {
  
  /** The policies that this service supports. */
  private final Map<String, IntegrationServiceConfiguration> policies;

  /**
   * Constructor.
   * 
   * @param policies
   *          a mapping between policy names and service configuration objects
   */
  public DefaultConfigurationManager(final Map<String, IntegrationServiceConfiguration> policies) {
    this.policies = policies;
    if (this.policies.isEmpty()) {
      throw new IllegalArgumentException("At least one policy must be configured");
    }
    if (!this.policies.containsKey(IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME)) {
      throw new IllegalArgumentException("There must be a policy named 'default'");
    }
  }

  /** {@inheritDoc} */
  @Override
  public IntegrationServiceConfiguration getConfiguration(final String policy) {
    final String _policy = policy != null ? policy : IntegrationServiceDefaultConfiguration.DEFAULT_POLICY_NAME;
    return this.policies.get(_policy);
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getPolicies() {
    return this.policies.entrySet().stream().map(m -> m.getKey()).collect(Collectors.toList());
  }

}
