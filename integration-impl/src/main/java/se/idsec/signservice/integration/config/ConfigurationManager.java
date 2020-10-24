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
package se.idsec.signservice.integration.config;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Interface for managing integration service configurations/policies.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ConfigurationManager {

  /**
   * Given the name of a SignService Integration policy, the method returns the service configuration used for this
   * policy.
   *
   * @param policy
   *          the policy name (null is interpreted as the default policy)
   * @return the service configuration for the given policy, or null if no policy is found
   */
  @Nullable
  IntegrationServiceConfiguration getConfiguration(@Nullable final String policy);

  /**
   * Returns a list of names of the policies that are defined for this instance of the SignService Integration Service.
   *
   * @return a non-empty list of policy names
   */
  @Nonnull
  List<String> getPolicies();

  /**
   * Gets the default policy name.
   * 
   * @return the default policy name
   */
  @Nonnull
  String getDefaultPolicyName();

  /**
   * Assigns the default policy name. If not assigned,
   * {@value IntegrationServiceDefaultConfiguration#DEFAULT_POLICY_NAME} will be used.
   * 
   * @param defaultPolicyName
   *          the default policy name
   */
  void setDefaultPolicyName(@Nonnull final String defaultPolicyName);

}
