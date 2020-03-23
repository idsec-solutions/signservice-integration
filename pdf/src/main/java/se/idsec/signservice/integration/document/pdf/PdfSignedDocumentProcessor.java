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

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.SignResponseProcessingParameters;
import se.idsec.signservice.integration.core.error.SignServiceIntegrationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractSignedDocumentProcessor;
import se.idsec.signservice.integration.document.impl.DefaultCompiledSignedDocument;
import se.idsec.signservice.integration.dss.SignRequestWrapper;
import se.swedenconnect.schemas.csig.dssext_1_1.SignTaskData;

/**
 * Signed document processor for PDF documents.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PdfSignedDocumentProcessor extends AbstractSignedDocumentProcessor<PDDocument, PadesObject> {

  /** The document decoder. */
  private static final PdfDocumentEncoderDecoder documentEncoderDecoder = new PdfDocumentEncoderDecoder();

  /** {@inheritDoc} */
  @Override
  public boolean supports(final SignTaskData signData) {
    return "PDF".equalsIgnoreCase(signData.getSigType());
  }

  /** {@inheritDoc} */
  @Override
  public CompiledSignedDocument<PDDocument, PadesObject> buildSignedDocument(
      final TbsDocument tbsDocument, 
      final SignTaskData signedData,
      final List<X509Certificate> signerCertificateChain, 
      final SignRequestWrapper signRequest, 
      final SignResponseProcessingParameters parameters) throws SignServiceIntegrationException {
    
    log.debug("{}: Compiling signed PDF document for Sign task '{}' ... [request-id='{}']",
      CorrelationID.id(), signedData.getSignTaskId(), signRequest.getRequestID());

    // First decode the original input document into a PDDocument object ...
    //
    final PDDocument document = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());
    
    // TODO: insert the signature and everything that is needed ...    
    // TODO: Check if we received a Pades object ...
    //
    PadesObject padesObject = null;
    
    return new DefaultCompiledSignedDocument<PDDocument, PadesObject>(
        signedData.getSignTaskId(), document, DocumentType.PDF.getMimeType(), this.getDocumentEncoder(), padesObject);
  }

  /** {@inheritDoc} */
  @Override
  public void validateSignedDocument(final PDDocument signedDocument, 
      final X509Certificate signerCertificate, 
      final SignTaskData signTaskData,
      final SignResponseProcessingParameters parameters, 
      final String requestID) throws SignServiceIntegrationException {
    
    log.debug("{}: Validating signed XML document for Sign task '{}' ... [request-id='{}']",
      CorrelationID.id(), signTaskData.getSignTaskId(), requestID);
    
    // TODO
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

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();
    
    // TODO: Any checks of required properties ... Use org.springframework.util.Assert
    
  }
  
  
}
