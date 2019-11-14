/*
 * Copyright 2019 IDsec Solutions AB
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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import se.idsec.signservice.integration.core.Extensible;
import se.idsec.signservice.integration.core.Extension;
import se.idsec.signservice.integration.core.ObjectBuilder;

/**
 * Represents a document that is to be signed along with the per-document requirements and parameters.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TbsDocument implements Extensible {

  /**
   * The unique ID for this document (within the current request). If not supplied, the SignService Integration Service
   * will generate one.
   * 
   * @param id
   *          unique ID for this document
   * @return unique ID for this document, or null if none has been set
   */
  @Setter
  @Getter
  private String id;

  /**
   * The Base64-encoded byte string that is the content of the document that is to be signed.
   * 
   * @param content
   *          the document content (Base64-encoded)
   * @return the document content (Base64-encoded)
   */
  @Setter
  @Getter
  private String content;

  /**
   * The MIME type of the document that is to be signed. See {@link DocumentType} for the supported types.
   * 
   * @return the MIME type
   */
  @Getter
  private String mimeType;

  /**
   * Optional processing rules used by the sign service to process sign data.
   * 
   * @param processingRules
   *          the processing rules
   * @return the processing rules identifier, or null if none has been set
   */
  @Setter
  @Getter
  private String processingRules;

  /**
   * Specifies of the resulting signature should use an ETSI AdES format.
   * 
   * @param adesRequirement
   *          the AdES requirement
   * @return the AdES requirement or null if no AdES requirement exists
   */
  @Setter
  @Getter
  private EtsiAdesFormatRequirement adesRequirement;

  /** Extensions for the object. */
  private Extension extension;

  /**
   * The MIME type of the document that is to be signed. See {@link DocumentType} for the supported types.
   * 
   * @param mimeType
   *          the document MIME type
   * @see #setMimeType(DocumentType)
   */
  public void setMimeType(final String mimeType) {
    this.mimeType = mimeType;
  }

  /**
   * The document type of the document that is to be signed.
   * 
   * @param documentType
   *          the document type
   */
  public void setMimeType(final DocumentType documentType) {
    this.mimeType = documentType != null ? documentType.getMimeType() : null;
  }

  /**
   * Assigns an extension object with extension parameters.
   * 
   * @param extension
   *          the extension object to assign
   */
  public void setExtension(Extension extension) {
    this.extension = extension;
  }

  /** {@inheritDoc} */
  @Override
  public Extension getExtension() {
    return this.extension;
  }

  /**
   * Builder for {@code TbsDocument} objects.
   */
  public static class TbsDocumentBuilder implements ObjectBuilder<TbsDocument> {
    // Lombok will generate code ...

    public TbsDocumentBuilder mimeType(final DocumentType mimeType) {
      this.mimeType = mimeType != null ? mimeType.getMimeType() : null;
      return this;
    }
  }

  /**
   * Enum reprenting an ETSI AdES format.
   */
  public static enum AdesType {
    /** ETSI Basic Electronic Signature format */
    BES,
    /** ETSI Extended Policy Electronic Signature format */
    EPES;
  }

  /**
   * Representation of an ETSI AdES signature format.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  @ToString
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class EtsiAdesFormatRequirement {

    /**
     * The ETSI AdES format type.
     * 
     * @param adesFormat
     *          the format
     * @return the format
     */
    @Setter
    @Getter
    private AdesType adesFormat;

    /**
     * The signature policy (required for EPES).
     * 
     * @param signaturePolicy
     *          the signature policy
     * @return the signature policy
     */
    @Setter
    @Getter
    private String signaturePolicy;

  }

}
