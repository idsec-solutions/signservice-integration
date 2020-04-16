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

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.util.StringUtils;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.*;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesRequirement;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.idsec.signservice.integration.document.impl.EtsiAdesRequirementValidator;
import se.idsec.signservice.integration.document.impl.TbsCalculationResult;
import se.idsec.signservice.integration.document.pdf.utils.PdfIntegrationUtils;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.impl.StaticCredentials;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSigner;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * PDF TBS-document processor.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfTbsDocumentProcessor extends AbstractTbsDocumentProcessor<PDFSignTaskDocument> {

  /** We need to use dummy keys when creating the to-be-signed bytes. */
  private final StaticCredentials staticKeys = new StaticCredentials();

  /** Validator for visible PDF signature requirements. */
  protected final VisiblePdfSignatureRequirementValidator visiblePdfSignatureRequirementValidator =
    new VisiblePdfSignatureRequirementValidator();

  /** Document decoder. */
  protected final static PdfSignTaskDocumentEncoderDecoder documentEncoderDecoder = new PdfSignTaskDocumentEncoderDecoder();

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
  public ProcessedTbsDocument preProcess(final TbsDocument document, final SignRequestInput signRequestInput, final IntegrationServiceConfiguration config, final String fieldName)
    throws InputValidationException {

    final ProcessedTbsDocument processedTbsDocument = super.preProcess(document, signRequestInput, config, fieldName);
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

    EtsiAdesRequirement requestedAdes = document.getAdesRequirement();
    String ades = PdfIntegrationUtils.getPadesRequirementString(requestedAdes);
    PDFSignTaskDocument signTaskDocument = processedTbsDocument.getDocumentObject(PDFSignTaskDocument.class);
    signTaskDocument.setAdesType(ades);

    //TODO Set visible signature object

    return processedTbsDocument;
  }

  /** {@inheritDoc} */
  @Override
  protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
    IntegrationServiceConfiguration config) throws DocumentProcessingException {

    TbsDocument tbsDocument = document.getTbsDocument();
    try {
      DefaultPDFSigner signer = new DefaultPDFSigner(staticKeys.getSigningCredential(signatureAlgorithm), signatureAlgorithm);
      PDFSignTaskDocument signTaskDocument = document.getDocumentObject(PDFSignTaskDocument.class);
      signer.setIncludeCertificateChain(false);
      PDFSignerResult pdfSignerResult = signer.sign(signTaskDocument);
      TbsCalculationResult tbsResult = TbsCalculationResult.builder()
        .toBeSignedBytes(pdfSignerResult.getSignedAttributes())
        .sigType("PDF")
        .build();

      //Set extension in TbsDocument with the PDF signature ID and time
      Extension extension = tbsDocument.getExtension();
      if (extension == null) {
        extension = Extension.builder().build();
        tbsDocument.setExtension(extension);
      }
      extension.putIfAbsent(PDFExtensionParams.signTimeAndId.name(), String.valueOf(pdfSignerResult.getSigningTime()));
      extension.putIfAbsent(PDFExtensionParams.cmsSignedData.name(),
        Base64.toBase64String(pdfSignerResult.getSignedDocument().getCmsSignedData()));

      return tbsResult;

    }
    catch (NoSuchAlgorithmException | SignatureException e) {
      final String msg = String.format("Error while calculating signed attributes for PDF document '%s' - %s",
        tbsDocument.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new DocumentProcessingException(new ErrorCode.Code("sign"), msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<PDFSignTaskDocument> getDocumentDecoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<PDFSignTaskDocument> getDocumentEncoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  protected EtsiAdesRequirementValidator getEtsiAdesRequirementValidator() {
    return new PadesRequirementValidator();
  }

  /**
   * Validator for {@link EtsiAdesRequirement} objects.
   */
  public static class PadesRequirementValidator extends EtsiAdesRequirementValidator {

    /** {@inheritDoc} */
    @Override
    public ValidationResult validate(EtsiAdesRequirement object, String objectName, Void hint) {
      ValidationResult result = new ValidationResult(objectName);
      if (object == null) {
        return result;
      }

      if (TbsDocument.AdesType.EPES.equals(object.getAdesFormat()) && !StringUtils.hasText(object.getSignaturePolicy())) {
        result.rejectValue("signaturePolicy",
          "AdES requirement states Extended Policy Electronic Signature but no signature policy has been given");
      }

      // TODO: Validate the input ...

      return result;
    }

  }

}
