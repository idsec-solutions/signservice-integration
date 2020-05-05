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
  public DefaultCompiledSignedDocument(final String id, final T document, final String mimeType, final DocumentEncoder<T> documentEncoder) {
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
  public DefaultCompiledSignedDocument(final String id, final T document, final String mimeType,
      final DocumentEncoder<T> documentEncoder, final X adesObject) {
    if (id == null) {
      throw new IllegalArgumentException("id must not be null");
    }
    this.id = id;
    if (document == null) {
      throw new IllegalArgumentException("document must not be null");
    }
    this.document = document;
    if (mimeType == null) {
      throw new IllegalArgumentException("mimeType must not be null");
    }
    this.mimeType = mimeType;
    if (documentEncoder == null) {
      throw new IllegalArgumentException("documentEncoder must not be null");
    }
    this.documentEncoder = documentEncoder;
    this.adesObject = adesObject;
  }

  /** {@inheritDoc} */
  @Override
  public T getDocument() {
    return this.document;
  }

  /** {@inheritDoc} */
  @Override
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
  public X getAdesObject() {
    return this.adesObject;
  }

}
