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
package se.idsec.signservice.integration.document.impl;

import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocumentProcessor;
import se.swedenconnect.schemas.csig.dssext_1_1.AdESObject;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Abstract base class for {@link TbsDocumentProcessor} implementations.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractTbsDocumentProcessor<T> implements TbsDocumentProcessor<T> {

  /** Validator. */
  protected final TbsDocumentValidator tbsDocumentValidator = new TbsDocumentValidator();

  /** Object factory for DSS-Ext objects. */
  private static se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory dssExtObjectFactory =
      new se.swedenconnect.schemas.csig.dssext_1_1.ObjectFactory();
  
  /** {@inheritDoc} */
  @Override
  public ProcessedTbsDocument preProcess(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException {

    // Make a copy of the document before updating it.
    TbsDocument updatedDocument = document.toBuilder().build();

    if (document.getId() == null) {
      updatedDocument.setId(UUID.randomUUID().toString());
      log.info("{}: No document ID assigned to document, assigning generated id: {}", CorrelationID.id(), updatedDocument.getId());
    }

    if (document.getAdesRequirement() != null && document.getAdesRequirement().getAdesFormat() == null) {
      log.warn("{}: No AdES format assigned for AdES requirement for document '{}'", CorrelationID.id(), updatedDocument.getId());
      updatedDocument.setAdesRequirement(null);
    }

    // Validate
    this.tbsDocumentValidator.validateObject(updatedDocument, fieldName, null);

    // Validate the document content ...
    //
    final T validatedContent = this.validateDocumentContent(updatedDocument, config, fieldName);

    return new ProcessedTbsDocument(updatedDocument, validatedContent);
  }

  /** {@inheritDoc} */
  @Override
  public final SignTaskData process(final ProcessedTbsDocument document, final String signatureAlgorithm,
      final IntegrationServiceConfiguration config) throws DocumentProcessingException {

    final TbsCalculationResult tbsCalculation = this.calculateToBeSigned(document, signatureAlgorithm, config);
    final TbsDocument tbsDocument = document.getTbsDocument();

    SignTaskData signTaskData = dssExtObjectFactory.createSignTaskData();
    signTaskData.setSignTaskId(tbsDocument.getId());
    signTaskData.setSigType(tbsCalculation.getSigType());
    signTaskData.setToBeSignedBytes(tbsCalculation.getToBeSignedBytes());
    if (tbsDocument.getAdesRequirement() != null) {
      signTaskData.setAdESType(tbsDocument.getAdesRequirement().getAdesFormat().name());
      if (tbsCalculation.getAdesSignatureId() != null) {
        AdESObject adesObject = dssExtObjectFactory.createAdESObject();
        adesObject.setSignatureId(tbsCalculation.getAdesSignatureId());
        if (tbsCalculation.getAdesObjectBytes() != null) {
          adesObject.setAdESObjectBytes(tbsCalculation.getAdesObjectBytes());
        }
        signTaskData.setAdESObject(adesObject);
      }
    }
    else {
      signTaskData.setAdESType("None");
    }

    return signTaskData;
  }

  /**
   * Calculates the ToBeSignedBytes, and optionally AdES data, that will be part of the {@code SignTaskData}.
   * 
   * @param document
   *          the document to sign
   * @param signatureAlgorithm
   *          the signature algorithm to be used for signing the document
   * @param config
   *          the profile configuration
   * @return the TBS bytes and optionally AdES data
   * @throws SignServiceIntegrationException
   *           for processing errors
   */
  protected abstract TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
      final IntegrationServiceConfiguration config) throws DocumentProcessingException;

  /**
   * Validates the document contents. The default implementation invokes {@link DocumentDecoder#decodeDocument(String)}.
   * 
   * @param document
   *          the document holding the content to validate
   * @param config
   *          the current policy configuration
   * @param fieldName
   *          used for error reporting and logging
   * @return the contents represented according to the document format
   * @throws InputValidationException
   *           for validation errors
   */
  protected T validateDocumentContent(
      final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException {
    
    try {
      final T documentObject = this.getDocumentDecoder().decodeDocument(document.getContent());
      log.debug("{}: Successfully validated document (doc-id: {})", CorrelationID.id(), document.getId());
      return documentObject;
    }
    catch (DocumentProcessingException e) {
      final String msg = String.format("Failed to load content for document '%s' - %s", document.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new InputValidationException(fieldName + ".content", msg, e);
    }
  }

}
