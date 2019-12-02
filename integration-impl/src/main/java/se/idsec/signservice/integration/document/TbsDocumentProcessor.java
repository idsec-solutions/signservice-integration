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
package se.idsec.signservice.integration.document;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.BadRequestException;

/**
 * Interface for a processor of a "to be signed" document.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface TbsDocumentProcessor {

  /**
   * Predicate that tells if the supplied document can be handled by this processor.
   * 
   * @param document
   *          the document
   * @return if the document can be processed by this instance true is returned, otherwise false
   */
  boolean supports(final TbsDocument document);

  /**
   * Performs a pre-processing of the supplied document where the document is validated, and in some cases updated with
   * default settings.
   * 
   * @param correlationId
   *          the correlation ID (used for logging)
   * @param document
   *          the document to process
   * @param config
   *          the current policy configuration
   * @param fieldName
   *          used for error reporting and logging
   * @return a (possibly updated) document
   * @throws BadRequestException
   *           for validation errors
   */
  TbsDocument preProcess(final String correlationId, final TbsDocument document, 
      final IntegrationServiceConfiguration config, final String fieldName) throws BadRequestException;

  // TODO

}
