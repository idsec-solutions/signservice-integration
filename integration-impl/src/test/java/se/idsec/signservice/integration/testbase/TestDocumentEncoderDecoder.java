/*
 * Copyright 2019-2025 IDsec Solutions AB
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
package se.idsec.signservice.integration.testbase;

import lombok.Setter;
import se.idsec.signservice.integration.core.error.ErrorCode;
import se.idsec.signservice.integration.document.DocumentDecoder;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;

public class TestDocumentEncoderDecoder
    implements DocumentEncoder<TestDocumentType>, DocumentDecoder<TestDocumentType> {

  @Setter
  private boolean failEncode = false;

  @Setter
  private boolean failDecode = false;

  @Override
  public TestDocumentType decodeDocument(String content) throws DocumentProcessingException {
    if (this.failDecode) {
      throw new DocumentProcessingException(new ErrorCode.Code("error"), "error");
    }
    return new TestDocumentType(content);
  }

  @Override
  public String encodeDocument(TestDocumentType document) throws DocumentProcessingException {
    if (this.failEncode) {
      throw new DocumentProcessingException(new ErrorCode.Code("error"), "error");
    }
    return document.getContents();
  }

}
