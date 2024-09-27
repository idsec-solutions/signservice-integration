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
package se.idsec.signservice.integration.document;

/**
 * Document decoder interface.
 *
 * @param <T> document type
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface DocumentDecoder<T> {

  /**
   * Given the document content (in Base64 encoded form), the document object is returned.
   *
   * @param content the document in Base64 encoded format
   * @return the document object
   * @throws DocumentProcessingException for decoding errors
   */
  T decodeDocument(final String content) throws DocumentProcessingException;

}
