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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;

import org.apache.commons.lang.StringUtils;
import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignRequestInput;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.TbsDocument.EtsiAdesRequirement;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.idsec.signservice.integration.document.impl.EtsiAdesRequirementValidator;
import se.idsec.signservice.integration.document.impl.TbsCalculationResult;
import se.idsec.signservice.integration.document.pdf.utils.PDFIntegrationUtils;
import se.idsec.signservice.integration.document.pdf.visiblesig.VisiblePdfSignatureRequirementException;
import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSignatureImageFactory;
import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSignatureImageSerializer;
import se.idsec.signservice.security.sign.AdesProfileType;
import se.idsec.signservice.security.sign.impl.StaticCredentials;
import se.idsec.signservice.security.sign.pdf.PDFSignerParameters;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.impl.DefaultPDFSigner;

/**
 * PDF TBS-document processor.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfTbsDocumentProcessor extends AbstractTbsDocumentProcessor<byte[]> {

  /** We need to use dummy keys when creating the to-be-signed bytes. */
  private final StaticCredentials staticKeys = new StaticCredentials();

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
  public ProcessedTbsDocument preProcess(final TbsDocument document, final SignRequestInput signRequestInput,
      final IntegrationServiceConfiguration config, final String fieldName) throws InputValidationException {

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

      // Is this a "null" request. If so, remove it ...
      //
      if (Boolean.valueOf(tbsDocument.getVisiblePdfSignatureRequirement()
        .getExtensionValue(
          NullVisiblePdfSignatureRequirement.NULL_INDICATOR_EXTENSION))) {

        log.debug("{}: Document '{}' contains a null requirement, removing ...",
          CorrelationID.id(), tbsDocument.getId());
        tbsDocument.setVisiblePdfSignatureRequirement(null);
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
    }

    // AdES requirements ...
    //
    final EtsiAdesRequirement requestedAdes = tbsDocument.getAdesRequirement();
    final AdesProfileType ades = PDFIntegrationUtils.getPadesRequirement(requestedAdes);
    tbsDocument.addExtensionValue(PDFExtensionParams.adesRequirement.name(), ades.getStringValue());

    // Visible PDF signature requirements ...
    //
    final VisiblePdfSignatureRequirement visiblePdfSignatureRequirement = tbsDocument.getVisiblePdfSignatureRequirement();
    if (visiblePdfSignatureRequirement != null) {
      final VisibleSignatureImageFactory factory = new VisibleSignatureImageFactory(config.getPdfSignatureImageTemplates());
      try {
        final String encodedVisibleSignImage = factory.getEncodedVisibleSignImage(
          visiblePdfSignatureRequirement, signRequestInput.getAuthnRequirements().getRequestedSignerAttributes());
        tbsDocument.addExtensionValue(PDFExtensionParams.visibleSignImage.name(), encodedVisibleSignImage);
      }
      catch (VisiblePdfSignatureRequirementException e) {
        throw new InputValidationException(fieldName + ".visiblePdfSignatureRequirement", e.getMessage(), e);
      }
    }

    return processedTbsDocument;
  }

  /** {@inheritDoc} */
  @Override
  protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
      IntegrationServiceConfiguration config) throws DocumentProcessingException {

    final TbsDocument tbsDocument = document.getTbsDocument();

    // Sign the document using a fake key - in order to obtain the to-be-signed bytes.
    //
    try {
      final DefaultPDFSigner signer = new DefaultPDFSigner(staticKeys.getSigningCredential(signatureAlgorithm), signatureAlgorithm);
      signer.setIncludeCertificateChain(false);

      final String padesString = tbsDocument.getExtensionValue(PDFExtensionParams.adesRequirement.name());
      final String encodedVisibleImage = tbsDocument.getExtensionValue(PDFExtensionParams.visibleSignImage.name());

      final PDFSignerParameters signerParameters = PDFSignerParameters.builder()
        .padesType(padesString != null ? AdesProfileType.fromStringValue(padesString) : null)
        .visibleSignatureImage(
          encodedVisibleImage != null ? VisibleSignatureImageSerializer.deserializeVisibleSignImage(encodedVisibleImage) : null)
        .build();

      final PDFSignerResult pdfSignerResult = signer.sign(document.getDocumentObject(byte[].class), signerParameters);

      TbsCalculationResult tbsResult = TbsCalculationResult.builder()
        .toBeSignedBytes(pdfSignerResult.getSignedAttributes())
        .sigType("PDF")
        .build();

      // Set extensions in TbsDocument with the PDF signature ID and time
      //
      tbsDocument.addExtensionValue(PDFExtensionParams.signTimeAndId.name(), String.valueOf(pdfSignerResult.getSigningTime()));
      tbsDocument.addExtensionValue(PDFExtensionParams.cmsSignedData.name(),
        Base64.getEncoder().encodeToString(pdfSignerResult.getSignedData()));

      return tbsResult;
    }
    catch (NoSuchAlgorithmException | IllegalArgumentException | IOException | SignatureException e) {
      final String msg = String.format("Error while calculating signed attributes for PDF document '%s' - %s", tbsDocument.getId(), e
        .getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new DocumentProcessingException(new ErrorCode.Code("sign"), msg, e);
    }
  }

  /**
   * Overrides the default implementation and ensures that the bytes that makes up the PDF document really are OK, that
   * is, we ensure that they can be loaded into a {@link PDDocument}.
   */
  @Override
  protected byte[] validateDocumentContent(final TbsDocument document, final IntegrationServiceConfiguration config, final String fieldName)
      throws InputValidationException {

    final byte[] pdfDocumentBytes = super.validateDocumentContent(document, config, fieldName);
    try {
      InputStream is = new ByteArrayInputStream(pdfDocumentBytes);
      PDDocument pdfDocument = PDDocument.load(is);
      pdfDocument.close();
    }
    catch (Exception e) {
      final String msg = String.format("Failed to load content for document '%s' - %s", document.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new InputValidationException(fieldName + ".content", msg, e);
    }
    return pdfDocumentBytes;
  }

  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<byte[]> getDocumentDecoder() {
    return documentEncoderDecoder;
  }

  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<byte[]> getDocumentEncoder() {
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

      if (TbsDocument.AdesType.EPES.equals(object.getAdesFormat()) && StringUtils.isBlank(object.getSignaturePolicy())) {
        result.rejectValue("signaturePolicy",
          "AdES requirement states Extended Policy Electronic Signature but no signature policy has been given");
      }

      return result;
    }

  }

}
