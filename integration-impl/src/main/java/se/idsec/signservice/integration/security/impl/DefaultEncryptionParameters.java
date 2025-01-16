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
package se.idsec.signservice.integration.security.impl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.XMLCipher;
import se.idsec.signservice.integration.core.ObjectBuilder;
import se.idsec.signservice.integration.security.EncryptionParameters;

import java.io.Serial;

/**
 * Default implementation of the {@link EncryptionParameters} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DefaultEncryptionParameters implements EncryptionParameters {

  @Serial
  private static final long serialVersionUID = 5475705400371189456L;

  /** The default data encryption algorithm is AES-128 GCM. */
  public static final String DEFAULT_DATA_ENCRYPTION_ALGORITHM = XMLCipher.AES_128_GCM;

  /** The default key transport encryption algorithm is RSA OAEP MGF1P. */
  public static final String DEFAULT_KEY_TRANSPORT_ENCRYPTION_ALGORITHM = XMLCipher.RSA_OAEP;

  /** The default RSA OAEP parameters. */
  public static final RSAOAEPParameters DEFAULT_RSA_OAEP_PARAMETERS = RSAOAEPParameters.builder()
      .digestMethod(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1)
      .maskGenerationFunction("http://www.w3.org/2009/xmlenc11#mgf1sha1")
      .build();

  /**
   * The data encryption algorithm that should be used when encrypting the sign message for a given Identity Provider.
   */
  @Setter
  @Builder.Default
  private String dataEncryptionAlgorithm = DEFAULT_DATA_ENCRYPTION_ALGORITHM;

  /**
   * The key transport encryption algorithm that should be used when encrypting the sign message for a given Identity
   * Provider.
   */
  @Setter
  @Builder.Default
  private String keyTransportEncryptionAlgorithm = DEFAULT_KEY_TRANSPORT_ENCRYPTION_ALGORITHM;

  /**
   * If {@link #getKeyTransportEncryptionAlgorithm()} returns {@code http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p} or
   * {@code http://www.w3.org/2009/xmlenc11#rsa-oaep}, this fields holds the RSA OAEP parameters to use.
   */
  @Builder.Default
  private RSAOAEPParameters rsaOaepParameters = DEFAULT_RSA_OAEP_PARAMETERS;

  /** {@inheritDoc} */
  @Override
  public String getDataEncryptionAlgorithm() {
    return this.dataEncryptionAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public String getKeyTransportEncryptionAlgorithm() {
    return this.keyTransportEncryptionAlgorithm;
  }

  /**
   * Assigns the RSA OAEP parameters.
   *
   * @param rsaOAEPParameters the RSA OAEP parameters
   */
  public void setRSAOAEPParameters(final RSAOAEPParameters rsaOAEPParameters) {
    this.rsaOaepParameters = rsaOAEPParameters;
  }

  /** {@inheritDoc} */
  @Override
  public RSAOAEPParameters getRsaOaepParameters() {
    return this.rsaOaepParameters;
  }

  /**
   * Builder for {@code DefaultEncryptionParameters} objects.
   */
  public static class DefaultEncryptionParametersBuilder implements ObjectBuilder<DefaultEncryptionParameters> {
    // Lombok
  }

}
