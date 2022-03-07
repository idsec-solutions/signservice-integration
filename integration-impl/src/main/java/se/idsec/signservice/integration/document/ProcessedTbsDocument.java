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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;

/**
 * Representation of a "processed" TBS document. This is basically the {@link TbsDocument} instance and its document
 * object (as a Java object).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ProcessedTbsDocument {

  /** The TbsDocument. */
  @Getter
  private final TbsDocument tbsDocument;

  /** The document as a Java object. */
  @Getter
  private final Object documentObject;

  /**
   * Constructor.
   *
   * @param tbsDocument
   *          the TbsDocument
   * @param documentObject
   *          the document as a Java object
   */
  public ProcessedTbsDocument(@Nonnull final TbsDocument tbsDocument, @Nullable final Object documentObject) {
    this.tbsDocument = tbsDocument;
    this.documentObject = documentObject;
  }

  /**
   * Gets the document object.
   *
   * @param type
   *          the required type
   * @param <T>
   *          the type
   * @return the document object or null
   */
  public <T> T getDocumentObject(final Class<T> type) {
    return this.documentObject != null ? type.cast(this.documentObject) : null;
  }

}
