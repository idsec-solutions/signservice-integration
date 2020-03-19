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
package se.idsec.signservice.integration.document;

import javax.annotation.Nonnull;

import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Interface for a processor of a "to be signed" document.
 * 
 * @param <T>
 *          the type of documents handled by this processor
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface TbsDocumentProcessor<T> extends DocumentProcessor<T> {

  /**
   * Predicate that tells if the supplied document can be handled by this processor.
   * 
   * @param document
   *          the document
   * @return if the document can be processed by this instance true is returned, otherwise false
   */
  boolean supports(@Nonnull final TbsDocument document);

  /**
   * Performs a pre-processing of the supplied document where the document is validated, and in some cases updated with
   * default settings.
   * 
   * @param document
   *          the document to process
   * @param config
   *          the current policy configuration
   * @param fieldName
   *          used for error reporting and logging
   * @return a processed (and possibly updated) document
   * @throws InputValidationException
   *           for validation errors
   */
  ProcessedTbsDocument preProcess(
      @Nonnull final TbsDocument document, @Nonnull final IntegrationServiceConfiguration config, @Nonnull final String fieldName)
      throws InputValidationException;

  /**
   * Prepares the document for signing by creating a {@code SignTaskData} element.
   * 
   * @param document
   *          the document to sign
   * @param signatureAlgorithm
   *          the signature algorithm to be used for signing the document
   * @param config
   *          profile configuration
   * @return a SignTaskData element
   * @throws DocumentProcessingException
   *           for processing errors
   */
  SignTaskData process(@Nonnull final ProcessedTbsDocument document, @Nonnull final String signatureAlgorithm,
      @Nonnull final IntegrationServiceConfiguration config) throws DocumentProcessingException;

}
