/*
 * Copyright 2019-2022 IDsec Solutions AB
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

import org.w3c.dom.Document;

import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.xml.DOMUtils;

/**
 * Encoder/decoder for XML documents.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class XmlDocumentEncoderDecoder implements DocumentDecoder<Document>, DocumentEncoder<Document> {

  /** {@inheritDoc} */
  @Override
  public Document decodeDocument(final String content) throws DocumentProcessingException {
    try {
      return DOMUtils.base64ToDocument(content);
    }
    catch (final Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("decode"), "Failed to decode XML object", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String encodeDocument(final Document document) throws DocumentProcessingException {
    try {
      return DOMUtils.nodeToBase64(document);
    }
    catch (final Exception e) {
      throw new DocumentProcessingException(new ErrorCode.Code("encode"), "Failed to encode XML object", e);
    }
  }

}
