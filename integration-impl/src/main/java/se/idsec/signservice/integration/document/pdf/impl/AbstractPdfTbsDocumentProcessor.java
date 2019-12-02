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
package se.idsec.signservice.integration.document.pdf.impl;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.BadRequestException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;

/**
 * Abstract base class for a PDF TBS-document processor.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractPdfTbsDocumentProcessor extends AbstractTbsDocumentProcessor {

  /** Validator for visible PDF signature requirements. */
  protected final VisiblePdfSignatureRequirementValidator visiblePdfSignatureRequirementValidator = new VisiblePdfSignatureRequirementValidator();

  /** {@inheritDoc} */
  @Override
  public boolean supports(final TbsDocument document) {
    try {
      return DocumentType.fromMimeType(document.getMimeType()) == DocumentType.PDF;
    }
    catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Handles settings for PDF visible signatures.
   */
  @Override
  public TbsDocument preProcess(final String correlationId, final TbsDocument document, 
      final IntegrationServiceConfiguration config, final String fieldName) throws BadRequestException {

    TbsDocument updatedDocument = super.preProcess(correlationId, document, config, fieldName);

    if (updatedDocument.getVisiblePdfSignatureRequirement() == null) {
      if (config.getDefaultVisiblePdfSignatureRequirement() != null) {
        log.debug("{}: Setting default value for visiblePdfSignatureRequirement ({}): {}",
          correlationId, updatedDocument.getId(), config.getDefaultVisiblePdfSignatureRequirement());
        updatedDocument.setVisiblePdfSignatureRequirement(config.getDefaultVisiblePdfSignatureRequirement());
      }
    }
    else {
      // Validate the input ...
      //
      this.visiblePdfSignatureRequirementValidator.validateObject(
        updatedDocument.getVisiblePdfSignatureRequirement(), fieldName + ".visiblePdfSignatureRequirement", config, correlationId);

      // Scale ...
      //
      if (updatedDocument.getVisiblePdfSignatureRequirement().getScale() == null) {
        log.info("{}: visiblePdfSignatureRequirement.scale is not set, defaulting to 0", correlationId);
        updatedDocument.getVisiblePdfSignatureRequirement().setScale(0);
      }
      else if (updatedDocument.getVisiblePdfSignatureRequirement().getScale().intValue() < -100) {
        log.info("{}: visiblePdfSignatureRequirement.scale is set to '{}'. This is illegal, changing to -100",
          correlationId, updatedDocument.getVisiblePdfSignatureRequirement().getScale());
        updatedDocument.getVisiblePdfSignatureRequirement().setScale(-100);
      }

      // Page ...
      //
      if (updatedDocument.getVisiblePdfSignatureRequirement().getPage() == null) {
        log.info("{}: visiblePdfSignatureRequirement.page is not set, defaulting to 0", correlationId);
        updatedDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
      if (updatedDocument.getVisiblePdfSignatureRequirement().getPage().intValue() < 0) {
        log.info("{}: visiblePdfSignatureRequirement.page is set to '{}'. This is illegal, changing to 0",
          correlationId, updatedDocument.getVisiblePdfSignatureRequirement().getPage());
        updatedDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
    }

    return updatedDocument;
  }

}
