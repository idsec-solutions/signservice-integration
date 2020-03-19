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
package se.idsec.signservice.integration.document.xml;

import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Base64;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.DocumentType;
import se.idsec.signservice.integration.document.ProcessedTbsDocument;
import se.idsec.signservice.integration.document.TbsDocument;
import se.idsec.signservice.integration.document.impl.AbstractTbsDocumentProcessor;
import se.idsec.signservice.integration.document.impl.TbsCalculationResult;
import se.idsec.signservice.security.sign.impl.StaticCredentials;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.xml.DOMUtils;

/**
 * Implementation of the XML TBS document processor.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XmlTbsDocumentProcessor extends AbstractTbsDocumentProcessor<Document> {

  /** We need to use dummy keys when creating the to-be-signed bytes. */
  private final StaticCredentials staticKeys = new StaticCredentials();
  
  /** The document decoder. */
  private static final XmlDocumentEncoderDecoder documentEncoderDecoder = new XmlDocumentEncoderDecoder();
    
  /**
   * Constructor.
   */
  public XmlTbsDocumentProcessor() {
  }
  
  /** {@inheritDoc} */
  @Override
  public boolean supports(final TbsDocument document) {
    try {
      return DocumentType.fromMimeType(document.getMimeType()) == DocumentType.XML;
    }
    catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** {@inheritDoc} */
  @Override
  protected TbsCalculationResult calculateToBeSigned(final ProcessedTbsDocument document, final String signatureAlgorithm,
      final IntegrationServiceConfiguration config) throws DocumentProcessingException {

    final TbsDocument tbsDocument = document.getTbsDocument();
    Document domDocument = document.getDocumentObject() != null ? document.getDocumentObject(Document.class) : null; 
    if (domDocument == null) {
      // Should never happen since we always set the document ...
      domDocument = this.getDocumentDecoder().decodeDocument(tbsDocument.getContent());
    }
    final boolean requireXadesSignature = tbsDocument.getAdesRequirement() != null; 

    // Sign the document using a fake key - in order to obtain the to-be-signed bytes.
    //
    try {
      
      final XMLSigner signer = DefaultXMLSigner.builder(this.staticKeys.getSigningCredential(signatureAlgorithm))
          .signatureAlgorithm(signatureAlgorithm)
          .setIncludeSignatureId(requireXadesSignature)
          .build();
 
      final XMLSignerResult preSignResult = signer.sign(domDocument);
      
      // Create result ...
      final TbsCalculationResult result = new TbsCalculationResult();
      result.setSigType("XML");
      
      // Include the canonicalized SignedInfo element.
      //
      result.setToBeSignedBytes(preSignResult.getCanonicalizedSignedInfo());
      
      if (log.isDebugEnabled()) {
        final Element signedInfo = preSignResult.getSignedInfo();
        log.debug("{}: Calculated SignedInfo for document '{}': {}", CorrelationID.id(), tbsDocument.getId(), DOMUtils.prettyPrint(signedInfo));
      }
      
      if (tbsDocument.getAdesRequirement() != null) {
        result.setAdesSignatureId(preSignResult.getSignatureElement().getAttribute(Constants._ATT_ID));        
        if (tbsDocument.getAdesRequirement().getAdesObject() != null) {
          result.setAdesObjectBytes(Base64.getDecoder().decode(tbsDocument.getAdesRequirement().getAdesObject()));
        }
      }
      
      return result;
    }
    catch (SignatureException | NoSuchAlgorithmException e) {
      final String msg = String.format("Error while calculating SignedInfo for document '%s' - %s", tbsDocument.getId(), e.getMessage());
      log.error("{}: {}", CorrelationID.id(), msg, e);
      throw new DocumentProcessingException(new ErrorCode.Code("sign"), msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public DocumentDecoder<Document> getDocumentDecoder() {
    return documentEncoderDecoder;
  }
  
  /** {@inheritDoc} */
  @Override
  public DocumentEncoder<Document> getDocumentEncoder() {
    return documentEncoderDecoder;
  }  

}
