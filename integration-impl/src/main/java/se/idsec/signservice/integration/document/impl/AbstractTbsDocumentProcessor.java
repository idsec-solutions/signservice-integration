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
package se.idsec.signservice.integration.document.impl;

import java.util.Base64;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
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
public abstract class AbstractTbsDocumentProcessor<T> implements TbsDocumentProcessor {

  /** Validator. */
  protected final TbsDocumentValidator tbsDocumentValidator = new TbsDocumentValidator();

  /** {@inheritDoc} */
  @Override
  public TbsDocument preProcess(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
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
    byte[] content;
    try {
      content = Base64.getDecoder().decode(document.getContent());
    }
    catch (IllegalArgumentException e) {
      final String msg =
          String.format("Supplied document content for document '%s' is not correctly Base64 encoded", updatedDocument.getId());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new InputValidationException(fieldName + ".content", msg, e);
    }
    T validatedContent = this.validateDocumentContent(content, updatedDocument, config, fieldName);
    if (validatedContent != null) {
      Extension extension = updatedDocument.getExtension() != null ? updatedDocument.getExtension() : new Extension();
      extension.put("validatedContent", validatedContent);
      updatedDocument.setExtension(extension);
    }

    return updatedDocument;
  }

  /** {@inheritDoc} */
  @Override
  public final SignTaskData process(final TbsDocument document, final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException {
    
    TbsCalculationResult tbsCalculation = this.calculateToBeSigned(document, config);
    
    SignTaskData signTaskData = new SignTaskData();
    signTaskData.setSignTaskId(document.getId());
    signTaskData.setSigType(tbsCalculation.getSigType());
    signTaskData.setToBeSignedBytes(tbsCalculation.getToBeSignedBytes());
    if (document.getAdesRequirement() != null) {
      signTaskData.setAdESType(document.getAdesRequirement().getAdesFormat().name());
      if (document.getAdesRequirement().getAdesFormat() == TbsDocument.AdesType.BES) {
        if (tbsCalculation.getAdesSignatureId() != null) {
          AdESObject adesObject = new AdESObject();
          adesObject.setSignatureId(tbsCalculation.getAdesSignatureId());
          if (tbsCalculation.getAdesObjectBytes() != null) {
            adesObject.setAdESObjectBytes(tbsCalculation.getAdesObjectBytes());
          }
          signTaskData.setAdESObject(adesObject);
        }
      }
      // else: EPES. TODO
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
   * @param config
   *          the profile configuration
   * @return the TBS bytes and optionally AdES data
   * @throws SignServiceIntegrationException
   *           for processing errors
   */
  protected abstract TbsCalculationResult calculateToBeSigned(final TbsDocument document, final IntegrationServiceConfiguration config)
      throws SignServiceIntegrationException;

  /**
   * Validates the document contents.
   * 
   * @param content
   *          the document content (in byte format)
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
  protected abstract T validateDocumentContent(
      final byte[] content, final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException;

  /**
   * Gets the validated document content
   * 
   * @param document
   *          the TBS document
   * @return the validated document content or null
   */
  protected T getValidatedContent(final TbsDocument document) {
    return document.getExtension() != null ? document.getExtension().get("validatedContent", this.getDocumentContentType()) : null;
  }

  /**
   * Gets the type of the validated document content that this processor handles.
   * 
   * @return the type
   */
  protected abstract Class<T> getDocumentContentType();

}
