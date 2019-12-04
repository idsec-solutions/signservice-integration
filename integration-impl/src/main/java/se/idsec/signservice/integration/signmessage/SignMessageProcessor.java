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
package se.idsec.signservice.integration.signmessage;

import javax.annotation.Nonnull;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.swedenconnect.schemas.csig.dssext_1_1.SignMessage;

/**
 * Processor for creating SignMessage objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignMessageProcessor {

  /**
   * Creates a {@code SignMessage} element and optionally encrypts it for the receipient.
   * 
   * @param input
   *          the (validated) parameters
   * @param config
   *          the SignService integration configuration
   * @return a SignMessage element
   * @throws SignServiceIntegrationException
   *           for processing errors
   */
  SignMessage create(@Nonnull final SignMessageParameters input, @Nonnull final IntegrationServiceConfiguration config) 
      throws SignServiceIntegrationException;

}
