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
package se.idsec.signservice.integration.process;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.idsec.signservice.integration.SignResponseCancelStatusException;
import se.idsec.signservice.integration.SignResponseErrorStatusException;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.SignatureResult;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.state.SignatureSessionState;

/**
 * Interface for sign response processing.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignResponseProcessor {

  /**
   * Processes the supplied SignResponse according to the supplied processing parameters and the session state.
   * 
   * @param signResponse
   *          the encoded SignResponse message
   * @param sessionState
   *          the state
   * @param config
   *          the policy configuration
   * @param parameters
   *          optional processing parameters
   * @return a signature response
   * @throws SignResponseCancelStatusException
   *           if the user cancelled the operation
   * @throws SignResponseErrorStatusException
   *           if the sign service reported an error
   * @throws SignServiceIntegrationException
   *           for processing and validation errors
   */
  @Nonnull
  SignatureResult processSignResponse(@Nonnull final String signResponse,
      @Nonnull final SignatureSessionState sessionState,
      @Nonnull final IntegrationServiceConfiguration config,
      @Nullable final SignResponseProcessingParameters parameters)
      throws SignResponseCancelStatusException, SignResponseErrorStatusException, SignServiceIntegrationException;

  /**
   * Gets the processing configuration that this processor is configured with.
   * 
   * @return the processing configuration
   */
  @Nonnull
  SignResponseProcessingConfig getProcessingConfiguration();

}
