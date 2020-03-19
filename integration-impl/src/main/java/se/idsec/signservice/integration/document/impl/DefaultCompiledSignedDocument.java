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
package se.idsec.signservice.integration.document.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.idsec.signservice.integration.document.CompiledSignedDocument;
import se.idsec.signservice.integration.document.DocumentEncoder;
import se.idsec.signservice.integration.document.DocumentProcessingException;
import se.idsec.signservice.integration.document.SignedDocument;
import se.idsec.signservice.integration.document.ades.AdesObject;

/**
 * Base class implementing the {@link CompiledSignedDocument} interface.
 * 
 * @param <T>
 *          the document type
 * @param <X>
 *          the AdES object from the signature
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultCompiledSignedDocument<T, X extends AdesObject> implements CompiledSignedDocument<T, X> {

  /** The sign task ID. */
  private final String id;

  /** The document. */
  private final T document;

  /** The document MIME type. */
  final String mimeType;

  /** The AdES object (may be null). */
  private final X adesObject;

  /** The document encoder. */
  private final DocumentEncoder<T> documentEncoder;

  /** The document encoding. */
  private String documentEncoding;

  /**
   * Constructor.
   * 
   * @param id
   *          the document ID
   * @param document
   *          the document
   * @param mimeType
   *          document MIME type
   * @param documentEncoder
   *          the document encoder
   */
  public DefaultCompiledSignedDocument(@Nonnull final String id, @Nonnull final T document, @Nonnull final String mimeType,
      @Nonnull final DocumentEncoder<T> documentEncoder) {
    this(id, document, mimeType, documentEncoder, null);
  }

  /**
   * Constructor.
   * 
   * @param id
   *          the document ID
   * @param document
   *          the document
   * @param mimeType
   *          document MIME type
   * @param adesObject
   *          AdES object (may be null)
   */
  public DefaultCompiledSignedDocument(@Nonnull final String id, @Nonnull final T document, @Nonnull final String mimeType,
      @Nonnull final DocumentEncoder<T> documentEncoder, @Nullable final X adesObject) {
    this.id = id;
    this.document = document;
    this.mimeType = mimeType;
    this.documentEncoder = documentEncoder;
    this.adesObject = adesObject;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public T getDocument() {
    return this.document;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public SignedDocument getSignedDocument() {
    if (this.documentEncoding == null) {
      try {
        this.documentEncoding = this.documentEncoder.encodeDocument(this.document);
      }
      catch (DocumentProcessingException e) {
        throw new RuntimeException(e);
      }
    }
    return SignedDocument.builder()
      .id(this.id)
      .signedContent(this.documentEncoding)
      .mimeType(this.mimeType)
      .build();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public X getAdesObject() {
    return this.adesObject;
  }

}
