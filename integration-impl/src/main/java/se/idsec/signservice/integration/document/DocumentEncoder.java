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
package se.idsec.signservice.integration.document;

/**
 * Document encoder interface.
 *
 * @param <T>
 *          the document type
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface DocumentEncoder<T> {

  /**
   * Encodes the supplied document into a Base64-encoding.
   *
   * @param document
   *          the document to encode
   * @return the Base64 encoded document
   * @throws DocumentProcessingException
   *           for encoding errors
   */
  String encodeDocument(final T document) throws DocumentProcessingException;

}
