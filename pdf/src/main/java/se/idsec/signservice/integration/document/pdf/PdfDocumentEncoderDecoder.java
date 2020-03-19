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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

import org.apache.pdfbox.pdmodel.PDDocument;

import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;

/**
 * Encoder/decoder for PDF documents.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PdfDocumentEncoderDecoder implements DocumentDecoder<PDDocument>, DocumentEncoder<PDDocument> {

  /** {@inheritDoc} */
  @Override
  public PDDocument decodeDocument(final String content) throws DocumentProcessingException {
    try {      
      InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(content));
      return PDDocument.load(is);
    }
    catch (Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("decode"), "Failed to load PDF object", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String encodeDocument(final PDDocument document) throws DocumentProcessingException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    BufferedOutputStream bos = new BufferedOutputStream(os);
    try {
      document.save(bos);
      bos.close();
      document.close();
      return Base64.getEncoder().encodeToString(os.toByteArray());
    }
    catch (Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("encode"), "Failed to encode PDF object", e);
    }
    finally {
      try {
        bos.close();
      }
      catch (IOException e) {        
      }
    }
  }

}
