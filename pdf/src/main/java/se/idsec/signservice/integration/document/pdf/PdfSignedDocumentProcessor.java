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
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.*;
import se.idsec.signservice.integration.document.impl.AbstractSignedDocumentProcessor;
import se.idsec.signservice.integration.document.impl.DefaultCompiledSignedDocument;
import se.idsec.signservice.integration.document.pdf.utils.PDFIntegrationUtils;
import se.idsec.signservice.integration.document.pdf.visiblesig.VisibleSigImageSerializer;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.idsec.signservice.integration.process.impl.SignResponseProcessingException;
import se.idsec.signservice.security.sign.pdf.PDFCompleteSigner;
import se.idsec.signservice.security.sign.pdf.PDFSignerResult;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgoRegistry;
import se.idsec.signservice.security.sign.pdf.document.PDFSignTaskDocument;
import se.idsec.signservice.security.sign.pdf.document.VisibleSigImage;
import se.idsec.signservice.security.sign.pdf.signprocess.PdfBoxSigUtil;
import se.idsec.signservice.security.sign.pdf.verify.BasicPdfSignatureVerifier;
import se.idsec.signservice.security.sign.pdf.verify.PdfSigVerifyResult;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

import javax.annotation.PostConstruct;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Signed document processor for PDF documents.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfSignedDocumentProcessor extends AbstractSignedDocumentProcessor<PDFSignTaskDocument, PAdESData> {

  /** Serializer to serialize and compress a VisibleSigImage object to and from a String value */
  private final VisibleSigImageSerializer visibleSigImageSerializer = new VisibleSigImageSerializer();

  /** The document decoder. */
  private static final PdfDocumentEncoderDecoder documentEncoderDecoder = new PdfDocumentEncoderDecoder();

  /** {@inheritDoc} */
  @Override
  public boolean supports(final SignTaskData signData) {
    return "PDF".equalsIgnoreCase(signData.getSigType());
  }

  /** {@inheritDoc} */
  @Override
  public CompiledSignedDocument<PDFSignTaskDocument, PAdESData> buildSignedDocument(
      final TbsDocument tbsDocument,
      final SignTaskData signedData,
      final List<X509Certificate> signerCertificateChain,
      final SignRequestWrapper signRequest,
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {

    try {
      log.debug("{}: Compiling signed PDF document for Sign task '{}' ... [request-id='{}']",
        CorrelationID.id(), signedData.getSignTaskId(), signRequest.getRequestID());

      // First decode the original input document into a PDFSignTaskDocument object ...
      //
      final PDFSignTaskDocument document = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());
      // Add the PDF signingTimeAndId
      try {
        Extension extension = tbsDocument.getExtension();
        Long signTimeAndId = Long.valueOf(extension.get(PDFExtensionParams.signTimeAndId.name()));
        byte[] cmsSignedData = Base64.decode(extension.get(PDFExtensionParams.cmsSignedData.name()));
        document.setSignTimeAndId(signTimeAndId);
        document.setCmsSignedData(cmsSignedData);
        if (extension.containsKey(PDFExtensionParams.visibleSignImage.name())){
          VisibleSigImage visibleSigImage = visibleSigImageSerializer.deserializeVisibleSignImage(
            extension.get(PDFExtensionParams.visibleSignImage.name()));
          document.setVisibleSigImage(visibleSigImage);
        }
      } catch (Exception ex){
        log.debug("Failed to process sign response. PDF document does not store the pre-sign signing time needed to complete the signed document assembly");
        throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"PDF document does not store the pre-sign signing time", ex);
      }
      // Set pades requirements
      document.setAdesType(PDFIntegrationUtils.getPadesRequirementString(tbsDocument.getAdesRequirement()));

      // Create complete signer and swap signature data
      PDFCompleteSigner completeSigner = new PDFCompleteSigner();
      PDFSignerResult pdfSignerResult = completeSigner.completeSign(document, signedData.getToBeSignedBytes(),
        signedData.getBase64Signature().getValue(), signerCertificateChain);

      //Check if we have PAdES data
      PAdESData padesData = null;
      PdfBoxSigUtil.SignedCertRef signedCertRefAttribute = PdfBoxSigUtil.getSignedCertRefAttribute(pdfSignerResult.getSignedAttributes());
      if (signedCertRefAttribute != null){
        PDFAlgoRegistry.PDFSignatureAlgorithmProperties algorithmProperties = PDFAlgoRegistry.getAlgorithmProperties(
          signedData.getBase64Signature().getType());
        if (!algorithmProperties.getDigestAlgoOID().equals(signedCertRefAttribute.getHashAlgorithm())){
          log.debug("PAdES object hash algorithm does not match signature algorithm");
          throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"PAdES object hash algorithm does not match signature algorithm");
        }
        padesData = new PAdESData(algorithmProperties.getDigestAlgoId(), signedCertRefAttribute.getSignedCertHash());
      }

      //Finally get the result signed pdf document
      PDFSignTaskDocument completeSignedDocument = pdfSignerResult.getSignedDocument();

      return new DefaultCompiledSignedDocument<PDFSignTaskDocument, PAdESData>(
        signedData.getSignTaskId(), completeSignedDocument, DocumentType.PDF.getMimeType(), this.getDocumentEncoder(), padesData);
    } catch (Exception ex){
      log.debug("Failed to assemble the final signed PDF document: {}", ex);
      throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"Failed to assemble the final signed PDF document", ex);
    }

  }


  /** {@inheritDoc} */
  @Override
  public void validateSignedDocument(final PDFSignTaskDocument signedDocument,
      final X509Certificate signerCertificate,
      final SignTaskData signTaskData,
      final SignResponseProcessingParameters parameters,
      final String requestID) throws SignServiceIntegrationException {

    log.debug("{}: Validating signed PDF document for Sign task '{}' ... [request-id='{}']",
      CorrelationID.id(), signTaskData.getSignTaskId(), requestID);

    try {
      PdfSigVerifyResult pdfSigVerifyResult = BasicPdfSignatureVerifier.verifyPdfSignatures(signedDocument.getPdfDocument());
      if (!pdfSigVerifyResult.isAllSigsValid()){
        if (pdfSigVerifyResult.isLastSigValid()){
          log.debug("Generated signature validates, but document contains invalid signatures");
          throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"Generated signature validates, but document contains invalid signatures");
        } else {
          log.debug("Generated signature fails signature validation");
          throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"Generated signature fails signature validation");
        }
      }
    }
    catch (Exception e) {
      log.debug("Signature validation fails with exception", e);
      throw new SignResponseProcessingException(new ErrorCode.Code("complete-sign"),"Generated signature fails signature validation", e);
    }
    log.debug("Signature validation success");
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
  @PostConstruct
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();
  }


}
