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
package se.idsec.signservice.integration.document.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.idsec.signservice.integration.document.impl.TbsCalculationResult;

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
  
  /** Document decoder. */
  protected final static PdfDocumentEncoderDecoder documentEncoderDecoder = new PdfDocumentEncoderDecoder();
  
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
  public ProcessedTbsDocument preProcess(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName) 
      throws InputValidationException {

    final ProcessedTbsDocument processedTbsDocument = super.preProcess(document, config, fieldName);  
    final TbsDocument tbsDocument = processedTbsDocument.getTbsDocument();

    if (tbsDocument.getVisiblePdfSignatureRequirement() == null) {
      if (config.getDefaultVisiblePdfSignatureRequirement() != null) {
        log.debug("{}: Setting default value for visiblePdfSignatureRequirement ({}): {}",
          CorrelationID.id(), tbsDocument.getId(), config.getDefaultVisiblePdfSignatureRequirement());
        tbsDocument.setVisiblePdfSignatureRequirement(config.getDefaultVisiblePdfSignatureRequirement());
      }
    }
    else {
      // Validate the input ...
      //
      this.visiblePdfSignatureRequirementValidator.validateObject(
        tbsDocument.getVisiblePdfSignatureRequirement(), fieldName + ".visiblePdfSignatureRequirement", config);

      // Scale ...
      //
      if (tbsDocument.getVisiblePdfSignatureRequirement().getScale() == null) {
        log.info("{}: visiblePdfSignatureRequirement.scale is not set, defaulting to 0", CorrelationID.id());
        tbsDocument.getVisiblePdfSignatureRequirement().setScale(0);
      }
      else if (tbsDocument.getVisiblePdfSignatureRequirement().getScale().intValue() < -100) {
        log.info("{}: visiblePdfSignatureRequirement.scale is set to '{}'. This is illegal, changing to -100",
          CorrelationID.id(), tbsDocument.getVisiblePdfSignatureRequirement().getScale());
        tbsDocument.getVisiblePdfSignatureRequirement().setScale(-100);
      }

      // Page ...
      //
      if (tbsDocument.getVisiblePdfSignatureRequirement().getPage() == null) {
        log.info("{}: visiblePdfSignatureRequirement.page is not set, defaulting to 0", CorrelationID.id());
        tbsDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
      if (tbsDocument.getVisiblePdfSignatureRequirement().getPage().intValue() < 0) {
        log.info("{}: visiblePdfSignatureRequirement.page is set to '{}'. This is illegal, changing to 0",
          CorrelationID.id(), tbsDocument.getVisiblePdfSignatureRequirement().getPage());
        tbsDocument.getVisiblePdfSignatureRequirement().setPage(0);
      }
    }

    return processedTbsDocument;
  }

  /** {@inheritDoc} */
  @Override
  protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm, 
      IntegrationServiceConfiguration config) throws DocumentProcessingException {

    return null;
  }
  
  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<PDDocument> getDocumentDecoder() {
    return documentEncoderDecoder;
  }
  
  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<PDDocument> getDocumentEncoder() {
    return documentEncoderDecoder;
  }  

}
