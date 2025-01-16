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
package se.idsec.signservice.integration.process;

import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;

import java.util.List;

/**
 * An interface that defines the operations for a SignRequest processor.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignRequestProcessor {

  /**
   * Performs validation of the supplied sign request input against the supplied configuration. The returned
   * {@code SignRequestInput} object is the supplied input updated with default values from the configuration.
   *
   * @param signRequestInput the sign request input
   * @param config the configuration under which we are processing the request
   * @param callerId optional ID for the calling entity
   * @return an updated sign request input object where all required fields are filled in
   * @throws InputValidationException if validation of the input fails
   */
  SignRequestInput preProcess(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config,
      final String callerId) throws InputValidationException;

  /**
   * Processes that sign request input and produces a {@code dss:SignRequest} message.
   *
   * @param signRequestInput the validated input
   * @param requestID the unique ID for this request
   * @param config configuration
   * @return the SignRequest
   * @throws SignServiceIntegrationException for processing errors
   */
  SignRequestProcessingResult process(final SignRequestInput signRequestInput, final String requestID,
      final IntegrationServiceConfiguration config) throws SignServiceIntegrationException;

  /**
   * Gets an unmutable list of installed processors for "to be signed" documents.
   *
   * @return the processors for tbsDocuments
   */
  List<TbsDocumentProcessor<?>> getTbsDocumentProcessors();

}
