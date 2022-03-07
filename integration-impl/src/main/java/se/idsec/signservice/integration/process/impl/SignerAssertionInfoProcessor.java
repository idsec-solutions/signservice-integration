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
package se.idsec.signservice.integration.process.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.authentication.SignerAssertionInformation;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.dss.SignResponseWrapper;
import se.idsec.signservice.integration.state.SignatureSessionState;

/**
 * Processor for handling the {@code SignerAssertionInfo} received in a {@code SignResponse}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignerAssertionInfoProcessor {

  /**
   * Processes and validates the {@code SignerAssertionInfo} received in the supplied {@code SignResponse} and creates a
   * {@code SignerAssertionInformation} object that is to be returned back to the caller.
   *
   * @param signResponse
   *          the SignResponse
   * @param state
   *          the state
   * @param parameters
   *          optional processing parameters
   * @return a SignerAssertionInformation object
   * @throws SignServiceIntegrationException
   *           for processing errors
   */
  SignerAssertionInformation processSignerAssertionInfo(@Nonnull final SignResponseWrapper signResponse,
      @Nonnull final SignatureSessionState state, @Nullable final SignResponseProcessingParameters parameters)
      throws SignServiceIntegrationException;

}
