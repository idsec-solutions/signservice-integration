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
package se.idsec.signservice.integration;

import java.util.List;

import se.idsec.signservice.integration.error.SignServiceIntegrationException;

/**
 * Interface describing the API for the SignService Integration Service.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignServiceIntegrationService {

  SignRequestData createSignRequest(SignRequestInput signRequestInput) throws SignServiceIntegrationException;

  /* xxx */ void processSignResponse(String signResponse, SignatureState state, SignResponseProcessingParameters parameters)
      throws SignServiceIntegrationException;

  /**
   * Given the name of a SignService Integration policy, the method returns the configuration used for this policy.
   * 
   * @param policy
   *          the policy name ({@code null} is interpreted as the default policy)
   * @return the service configuration for the given policy, or {@code null} if the given policy does not exist
   */
  IntegrationServiceConfiguration getConfiguration(String policy);

  /**
   * Returns a list of names of the policies that are defined for this instance of the SignService Integration Service.
   * 
   * @return a non-empty list of policy names
   */
  List<String> getPolicies();

}
