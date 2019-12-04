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
package se.idsec.signservice.integration.document.pdf;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * PDF TBS-document processor.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfTbsDocumentProcessor extends AbstractTbsDocumentProcessor<PDDocument> {

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
  public TbsDocument preProcess(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName) 
      throws InputValidationException {

    TbsDocument updatedDocument = super.preProcess(document, config, fieldName);

    if (updatedDocument.getVisiblePdfSignatureRequirement() == null) {
      if (config.getDefaultVisiblePdfSignatureRequirement() != null) {
        log.debug("{}: Setting default value for visiblePdfSignatureRequirement ({}): {}",
          CorrelationID.id(), updatedDocument.getId(), config.getDefaultVisiblePdfSignatureRequirement());
        updatedDocument.setVisiblePdfSignatureRequirement(config.getDefaultVisiblePdfSignatureRequirement());
      }
    }
    else {
      // Validate the input ...
      //
      this.visiblePdfSignatureRequirementValidator.validateObject(
        updatedDocument.getVisiblePdfSignatureRequirement(), fieldName + ".visiblePdfSignatureRequirement", config);

      // Scale ...
      //
      if (updatedDocument.getVisiblePdfSignatureRequirement().getScale() == null) {
        log.info("{}: visiblePdfSignatureRequirement.scale is not set, defaulting to 0", CorrelationID.id());
        updatedDocument.getVisiblePdfSignatureRequirement().setScale(0);
      }
      else if (updatedDocument.getVisiblePdfSignatureRequirement().getScale().intValue() < -100) {
        log.info("{}: visiblePdfSignatureRequirement.scale is set to '{}'. This is illegal, changing to -100",
          CorrelationID.id(), updatedDocument.getVisiblePdfSignatureRequirement().getScale());
        updatedDocument.getVisiblePdfSignatureRequirement().setScale(-100);
      }

      // Page ...
      //
      if (updatedDocument.getVisiblePdfSignatureRequirement().getPage() == null) {
        log.info("{}: visiblePdfSignatureRequirement.page is not set, defaulting to 0", CorrelationID.id());
        updatedDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
      if (updatedDocument.getVisiblePdfSignatureRequirement().getPage().intValue() < 0) {
        log.info("{}: visiblePdfSignatureRequirement.page is set to '{}'. This is illegal, changing to 0",
          CorrelationID.id(), updatedDocument.getVisiblePdfSignatureRequirement().getPage());
        updatedDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
    }

    return updatedDocument;
  }

  /** {@inheritDoc} */
  @Override
  public SignTaskData process(final TbsDocument document, final IntegrationServiceConfiguration config) throws SignServiceIntegrationException {
    // TODO: Implement
    return null;
  }

  /** {@inheritDoc} */
  @Override
  protected PDDocument validateDocumentContent(final byte[] content, final TbsDocument document, 
      final IntegrationServiceConfiguration config, final String fieldName) throws InputValidationException {
    
    // We want to load the PDF document in order to make sure it is a valid PDF document.
    //
    InputStream is = new ByteArrayInputStream(content);
    try {
      PDDocument pdf = PDDocument.load(is);
      log.debug("{}: Successfully validated PDF document (doc-id: {})", CorrelationID.id(), document.getId());
      return pdf;
    }
    catch (Exception e) {
      final String msg = String.format("Failed to load PDF content for document '%s' - %s", document.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new InputValidationException(fieldName + ".content", msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected Class<PDDocument> getDocumentContentType() {
    return PDDocument.class;
  }

}
