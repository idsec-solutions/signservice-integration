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

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractSignedDocumentProcessor;
import se.idsec.signservice.integration.document.impl.DefaultCompiledSignedDocument;
import se.idsec.signservice.integration.document.pdf.utils.PDFIntegrationUtils;
import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSigImageSerializer;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.process.impl.SignResponseProcessingException;
import se.idsec.signservice.security.sign.AdesProfileType;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.SignatureValidator;
import se.idsec.signservice.security.sign.pdf.PDFSignatureException;
import se.idsec.signservice.security.sign.pdf.SignServiceSignatureInterface;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgoRegistry;
import se.idsec.signservice.security.sign.pdf.document.VisibleSigImage;
import se.idsec.signservice.security.sign.pdf.impl.BasicPDFSignatureValidator;
import se.idsec.signservice.security.sign.pdf.signprocess.PDFSigningProcessor;
import se.idsec.signservice.security.sign.pdf.signprocess.PdfBoxSigUtil;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Signed document processor for PDF documents.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfSignedDocumentProcessor extends AbstractSignedDocumentProcessor<byte[], PAdESData> {

  /** The document decoder. */
  private static final PdfDocumentEncoderDecoder documentEncoderDecoder = new PdfDocumentEncoderDecoder();

  /** {@inheritDoc} */
  @Override
  public boolean supports(final SignTaskData signData) {
    return "PDF".equalsIgnoreCase(signData.getSigType());
  }

  /** {@inheritDoc} */
  @Override
  public CompiledSignedDocument<byte[], PAdESData> buildSignedDocument(
      final TbsDocument tbsDocument,
      final SignTaskData signedData,
      final List<X509Certificate> signerCertificateChain,
      final SignRequestWrapper signRequest,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    log.debug("{}: Compiling signed PDF document for Sign task '{}' ... [request-id='{}']",
      CorrelationID.id(), signedData.getSignTaskId(), signRequest.getRequestID());

    // First decode the original input document ...
    //
    final byte[] document = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());

    // Get the state parameters that we stored as extensions in the TbsDocument during the
    // pre-sign phase.
    //

    // SignTimeAndID
    //
    Long signTimeAndID = null;
    try {
      final String _signTimeAndID = getTbsDocumentExtension(tbsDocument, PDFExtensionParams.signTimeAndId.name());
      signTimeAndID = _signTimeAndID != null ? Long.valueOf(_signTimeAndID) : null;
    }
    catch (NumberFormatException e) {
    }
    if (signTimeAndID == null) {
      final String msg = String.format("Failed to process sign response (%s) - Missing SignTimeAndID in state [request-id='%s']",
        signedData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("state-error"), msg);
    }

    // CMS Signed data
    //
    final String encodedCmsSignedData = getTbsDocumentExtension(tbsDocument, PDFExtensionParams.cmsSignedData.name());
    final byte[] cmsSignedData = encodedCmsSignedData != null ? Base64.getDecoder().decode(encodedCmsSignedData) : null;
    if (cmsSignedData == null) {
      final String msg = String.format("Failed to process sign response (%s) - Missing CMS SignedData in state [request-id='%s']",
        signedData.getSignTaskId(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("state-error"), msg);
    }

    // Visible signature image
    //
    VisibleSigImage visibleSignatureImage = null;
    try {
      final String encodedVisibleSignatureImage = getTbsDocumentExtension(tbsDocument, PDFExtensionParams.visibleSignImage.name());
      visibleSignatureImage = encodedVisibleSignatureImage != null
          ? VisibleSigImageSerializer.deserializeVisibleSignImage(encodedVisibleSignatureImage)
          : null;
    }
    catch (IOException e) {
      final String msg = String.format(
        "Failed to process sign response (%s) - Invalid encoding of Visible signature image in state - %s [request-id='%s']",
        signedData.getSignTaskId(), e.getMessage(), signRequest.getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new SignResponseProcessingException(new ErrorCode.Code("state-error"), msg, e);
    }

    // AdES type
    //
    final AdesProfileType adesType = PDFIntegrationUtils.getPadesRequirement(tbsDocument.getAdesRequirement());

    // Now, put together the PDF signature that we prepared in the pre-sign phase.
    //
    try {
      final PDDocument pdfDocument = PDDocument.load(document);

      final SignServiceSignatureInterface replaceSignatureInterface = new ReplacingSignatureInterface(
        cmsSignedData,
        signedData.getToBeSignedBytes(),
        signedData.getBase64Signature().getValue(),
        signerCertificateChain,
        adesType);

      final PDFSigningProcessor.Result signResult = PDFSigningProcessor.signPdfDocument(
        pdfDocument, replaceSignatureInterface, signTimeAndID, visibleSignatureImage);

      // Check if we have PAdES data ...
      //
      PAdESData padesData = null;
      final PdfBoxSigUtil.SignedCertRef signedCertRefAttribute = PdfBoxSigUtil.getSignedCertRefAttribute(signResult
        .getCmsSignedAttributes());
      if (signedCertRefAttribute != null) {
        final PDFAlgoRegistry.PDFSignatureAlgorithmProperties algorithmProperties = PDFAlgoRegistry.getAlgorithmProperties(signedData
          .getBase64Signature()
          .getType());

        if (!algorithmProperties.getDigestAlgoOID().equals(signedCertRefAttribute.getHashAlgorithm())) {
          final String msg = String.format(
            "Error during PDF signature processing - PAdES object hash algorithm (%s) does not match signature algorithm (%s) [request-id='%s']",
            signedCertRefAttribute.getHashAlgorithm().getId(), signedData.getBase64Signature().getType(), signRequest.getRequestID());
          log.error("{}: {}", CorrelationID.id(), msg);
          throw new DocumentProcessingException(new ErrorCode.Code("ades-validation-error"), msg);
        }
        padesData = new PAdESData(algorithmProperties.getDigestAlgoId(), signedCertRefAttribute.getSignedCertHash());
      }

      log.debug("{}: Successful completion of PDF signature with task id '%s' [request-id='%s']",
        CorrelationID.id(), signedData.getSignTaskId(), signRequest.getRequestID());

      return new DefaultCompiledSignedDocument<byte[], PAdESData>(
        signedData.getSignTaskId(), signResult.getDocument(), DocumentType.PDF.getMimeType(), this.getDocumentEncoder(), padesData);
    }
    catch (PDFSignatureException | IOException | NoSuchAlgorithmException e) {
      final String msg = String.format("Failed to build signed PDF document - %s [request-id='%s']", e.getMessage(), signRequest
        .getRequestID());
      log.error("{}: {}", CorrelationID.id(), msg);
      throw new SignResponseProcessingException(new ErrorCode.Code("signature-processing"), msg, e);
    }

  }

  /** {@inheritDoc} */
  @Override
  public void validateSignedDocument(final byte[] signedDocument,
      final X509Certificate signerCertificate,
      final SignTaskData signTaskData,
      final SignResponseProcessingParameters parameters,
      final String requestID) throws SignServiceIntegrationException {

    log.debug("{}: Validating signed PDF document for Sign task '{}' ... [request-id='{}']",
      CorrelationID.id(), signTaskData.getSignTaskId(), requestID);

    try {
      final BasicPDFSignatureValidator signatureValidator = new BasicPDFSignatureValidator();
      final List<SignatureValidationResult> allResults = signatureValidator.validate(signedDocument);

      // We are mainly interested in the last signature (since that is the signature we actually verify) ...
      //
      final SignatureValidationResult result = allResults.get(allResults.size() - 1);

      if (!result.isSuccess()) {
        final String msg = String.format("Signature validation failed for sign task '%s' - %s - %s [request-id='%s']",
          signTaskData.getSignTaskId(), result.getStatus(), result.getStatusMessage(), requestID);
        log.error("{}: {}", CorrelationID.id());
        throw new DocumentProcessingException(new ErrorCode.Code("invalid-signature"), msg, result.getException());
      }
      else if (!SignatureValidator.isCompleteSuccess(allResults)) {
        log.warn(
          "{}: Signature validation for sign task '%s' was successful, but document contains other signatures that are invalid [request-id='%s']",
          CorrelationID.id(), signTaskData.getSignTaskId(), requestID);
      }
      else {
        // Make sure that the signature was signed by the given signer certificate ...
        //
        if (!signerCertificate.equals(result.getSignerCertificate())) {
          final String msg = String.format("Incorrect signature certificate for signature for sign task '%s' [request-id='%s']",
            signTaskData.getSignTaskId(), requestID);
          log.error("{}: {}", CorrelationID.id());
          throw new DocumentProcessingException(new ErrorCode.Code("invalid-signature"), msg, result.getException());
        }

        log.debug("{}: Signature validation for sign task '%s' succeeded", CorrelationID.id(), signTaskData.getSignTaskId());
      }
    }
    catch (SignatureException e) {
      log.debug("Signature validation fails with exception", e);
      throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"), "Generated signature fails signature validation", e);
    }
  }

  /**
   * Utility method that gets an extension from the supplied document
   * 
   * @param tbsDocument
   *          the document
   * @param extName
   *          the extension name
   * @return the extension value or null if it does not exist
   */
  private static String getTbsDocumentExtension(final TbsDocument tbsDocument, final String extName) {
    if (tbsDocument.getExtension() == null) {
      return null;
    }
    return tbsDocument.getExtension().get(extName);
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
  
  /**
   * Implementation of the SignatureInterface where the signature is constructed by replacing signature data in an
   * existing signature with data obtains from a remote signing service.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */  
  private static class ReplacingSignatureInterface implements SignServiceSignatureInterface {
    
    /** The original ContentInfo bytes holding SignedInfo from the original pre-signing process. */
    private final byte[] originalSignedData;

    /** The modified signed attributes provided from the signature service. */
    private final byte[] newSignedAttributesData;

    /** The signature value provided by the signature service. */
    private final byte[] newSignatureValue;

    /** The signer certificate chain provided by the signature service. */
    private final List<X509Certificate> signerCertchain;

    /** The updated Content Info holding SignedData. */
    private byte[] updatedCmsSignedData;

    /** The CMS Signed attributes. */
    private byte[] cmsSignedAttributes;
    
    /** PAdES flag. */
    private boolean pades;

    /**
     * Constructor for the replace signature interface implementation.
     *
     * @param originalSignedData
     *          the original ContentInfo bytes holding SignedInfo from the original pre-signing process
     * @param newSignedAttributesData
     *          the modified signed attributes provided from the signature service
     * @param newSignatureValue
     *          the signature value provided by the signature service
     * @param signerCertchain
     *          the signer certificate chain provided by the signature service
     * @param pades
     *          PAdES type (may be null)
     */
    public ReplacingSignatureInterface(final byte[] originalSignedData, final byte[] newSignedAttributesData,
        final byte[] newSignatureValue, final List<X509Certificate> signerCertchain, final AdesProfileType pades) {

      this.originalSignedData = originalSignedData;
      this.newSignedAttributesData = newSignedAttributesData;
      this.newSignatureValue = newSignatureValue;
      this.signerCertchain = signerCertchain;
      this.pades = pades != null && !AdesProfileType.None.equals(pades);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getCmsSignedData() {
      return this.updatedCmsSignedData;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getCmsSignedAttributes() {
      return this.cmsSignedAttributes;
    }

    /**
     * SignatureInterface implementation.
     * <p>
     * This method will be called from inside of the pdfbox and create the PKCS #7 signature (CMS ContentInfo). The given
     * InputStream contains the bytes that are given by the byte range.
     * </p>
     * <p>
     * In this implementation of the signature interface no new signature is created. Instead a previous pre-sign
     * signature is updated with signature value, signed attributes and certificates from a remote signature process
     * </p>
     *
     * @param content
     *          the message bytes being signed (specified by ByteRange in the signature dictionary)
     * @return CMS ContentInfo bytes holding the complete PKCS#7 signature structure
     * @throws IOException
     *           error during signature creation
     */
    @Override
    public byte[] sign(final InputStream content) throws IOException {
      try {
        this.updatedCmsSignedData = PdfBoxSigUtil.updatePdfPKCS7(
          this.originalSignedData, this.newSignedAttributesData, this.newSignatureValue, this.signerCertchain);
        this.cmsSignedAttributes = PdfBoxSigUtil.getCmsSignedAttributes(this.updatedCmsSignedData);
        return this.updatedCmsSignedData;
      }
      catch (PDFSignatureException e) {
        throw new IOException(e.getMessage(), e);
      }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isPades() {
      return this.pades;
    }

  }

}
