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
package se.idsec.signservice.integration.process;

import java.util.List;

import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.BadRequestException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;
import se.swedenconnect.schemas.dss_1_0.SignRequest;

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
   * @param signRequestInput
   *          the sign request input
   * @param config
   *          the configuration under which we are processing the request
   * @return an updated sign request input object where all required fields are filled in
   * @throws BadRequestException
   *           if the request input is fawlty
   */
  SignRequestInput preProcess(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config)
      throws BadRequestException;

  SignRequest process(final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException;

  // TODO

  /**
   * Gets an unmutable list of installed processors for "to be signed" documents.
   * 
   * @return the processors for tbsDocuments
   */
  List<TbsDocumentProcessor> getTbsDocumentProcessors();

}
