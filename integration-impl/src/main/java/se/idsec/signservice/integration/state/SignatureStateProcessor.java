/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.integration.state;

import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.SignatureState;
import se.idsec.signservice.integration.core.error.NoAccessException;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.process.SignRequestProcessor;

/**
 * A processor for handling signature states.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignatureStateProcessor {

  /**
   * Creates a signature state, and if the {@code stateless} flag is {@code false} also adds the state to the state
   * cache (see {@link #getStateCache()}).
   * <p>
   * The {@code requestInput} parameter that is passed must be a "complete" input object, meaning that the instance that
   * is passed must be the instance that is obtained from a call to
   * {@link SignRequestProcessor#preProcess(SignRequestInput, IntegrationServiceConfiguration, String)}.
   * </p>
   *
   * @param requestInput a fully populated sign request input
   * @param signRequest the SignRequest that is passed to the signature service
   * @param stateless tells whether this service is running is stateless mode or not
   * @param ownerId the ID for the caller (optional)
   * @return a SignatureState
   */
  SignatureState createSignatureState(final SignRequestInput requestInput, final SignRequestWrapper signRequest,
      final boolean stateless, final String ownerId);

  /**
   * Should be called during processing of a {@code SignResponse} message.
   * <p>
   * In the call to
   * {@link SignServiceIntegrationService#processSignResponse(String, String, SignatureState,
   * se.idsec.signservice.integration.SignResponseProcessingParameters)} that state is supplied by the caller. The state
   * that is supplied should be the same state as received from calling
   * {@link #createSignatureState(SignRequestInput, SignRequestWrapper, boolean, String)}.
   * </p>
   *
   * @param inputState the state received from the caller
   * @param requesterId the requesting actor's id (may be null)
   * @return a fully populated signature session state
   * @throws StateException for state errors
   * @throws NoAccessException if the state belongs to someone else (than requesterId)
   */
  SignatureSessionState getSignatureState(final SignatureState inputState, final String requesterId)
      throws StateException, NoAccessException;

  /**
   * Gets the state cache instance that is used by the processor.
   *
   * @return the IntegrationServiceStateCache instance
   */
  IntegrationServiceStateCache getStateCache();

}
