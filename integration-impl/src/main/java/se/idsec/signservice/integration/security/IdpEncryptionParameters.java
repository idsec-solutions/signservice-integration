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
package se.idsec.signservice.integration.security;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import se.idsec.signservice.integration.security.EncryptionParameters;

/**
 * The {@code IdpEncryptionParameters} represents the data needed for the SignService Integration Service when it should
 * encrypt a signature message that is to be encrypted for, and decrypted by, a SAML Identity Provider.
 * <p>
 * Normally, this information is obtained from the SAML metadata entry for the Identity Provider in combination with
 * default algorithm settings for the SignService Integration Service.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IdpEncryptionParameters extends EncryptionParameters {

  /**
   * Returns the Identity Provider encryption certificate holding the public key that should be used during the
   * encryption.
   * 
   * @return the certificate, or {@code null} if none is available (in some cases only a public key, but no certificate
   *         may be available)
   * @see #getEncryptionKey()
   */
  X509Certificate getEncryptionCertificate();

  /**
   * Return the public key that should be used when encrypting.
   * <p>
   * If an encryption certificate is available ({@link #getEncryptionCertificate()} returns a non-null value), this
   * method must equal {@link X509Certificate#getPublicKey()}.
   * </p>
   * 
   * @return the public key to be used during the encryption operation
   */
  PublicKey getEncryptionKey();

  /**
   * {@inheritDoc}
   * 
   * <p>
   * Implementations should first try to find a requsted algorithm specified by the indented recipient (that also
   * supported by the SignService Integration Service), or if no algorithm is specified use the default for the
   * SignService Integration Service.
   * </p>
   * <p>
   * The recipient (IdP) may for example specify requested/supported algorithms in SAML metadata.
   * </p>
   */
  @Override
  String getDataEncryptionAlgorithm();

  /**
   * {@inheritDoc}
   * 
   * <p>
   * Implementations should first try to find a requsted algorithm specified by the indented recipient (that also
   * supported by the SignService Integration Service), or if no algorithm is specified use the default for the
   * SignService Integration Service.
   * </p>
   * <p>
   * The recipient (IdP) may for example specify requested/supported algorithms in SAML metadata.
   * </p>
   */
  @Override
  String getKeyTransportEncryptionAlgorithm();

}
