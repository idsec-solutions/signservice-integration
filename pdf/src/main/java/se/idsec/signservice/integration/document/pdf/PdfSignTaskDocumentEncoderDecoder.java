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

import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.pdf.sign.PDFSignTaskDocument;

import java.util.Base64;

/**
 * Encoder/decoder for PDF documents.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfSignTaskDocumentEncoderDecoder implements DocumentDecoder<PDFSignTaskDocument>, DocumentEncoder<PDFSignTaskDocument> {

  /** {@inheritDoc} */
  @Override
  public PDFSignTaskDocument decodeDocument(final String content) throws DocumentProcessingException {
    try {
      return PDFSignTaskDocument.builder()
        .pdfDocumentBytes(Base64.getDecoder().decode(content))
        .build();
    }
    catch (Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("decode"), "Failed to load PDF object", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String encodeDocument(final PDFSignTaskDocument document) throws DocumentProcessingException {
    try {
      return Base64.getEncoder().encodeToString(document.getPdfDocumentBytes());
    }
    catch (Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("encode"), "Failed to encode PDF object", e);
    }
  }
}
