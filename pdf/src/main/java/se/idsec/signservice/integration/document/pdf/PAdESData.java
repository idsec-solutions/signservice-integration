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
package se.idsec.signservice.integration.document.pdf;

import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;

/**
 * This object holds PAdES specific data that is necessary to perform the extra validation procedures imposed by a PAdES
 * document such as validation of the signed certificate reference.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PAdESData implements AdesObject {

  /** The digest value and digest algorithm used to represent the signed certificate digest in PAdES. */
  private final AdesSigningCertificateDigest adesSigningCertificateDigest;

  /**
   * Constructor for the PAdES data object.
   *
   * @param digestMethod
   *          the URI for the digest method used to hash the signer certificate
   * @param digestValue
   *          the digest value
   */
  public PAdESData(final String digestMethod, final byte[] digestValue) {
    this.adesSigningCertificateDigest = new AdesSigningCertificateDigest(digestMethod, digestValue);
  }

  /** {@inheritDoc} */
  @Override
  public AdesSigningCertificateDigest getSigningCertificateDigest() {
    return this.adesSigningCertificateDigest;
  }

}
