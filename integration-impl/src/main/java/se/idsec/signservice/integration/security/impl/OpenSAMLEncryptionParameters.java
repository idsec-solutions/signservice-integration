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

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import se.idsec.signservice.integration.security.EncryptionParameters;

import java.io.Serial;

/**
 * Implementation of {@link EncryptionParameters} that uses OpenSAML's system configuration.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLEncryptionParameters implements EncryptionParameters {

  @Serial
  private static final long serialVersionUID = 3074989264317284157L;

  /** The OpenSAML system encryption configuration. */
  private final EncryptionConfiguration systemConfiguration;

  /**
   * Constructor.
   */
  public OpenSAMLEncryptionParameters() {
    this.systemConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
  }

  /** {@inheritDoc} */
  @Override
  public String getDataEncryptionAlgorithm() {
    return this.systemConfiguration.getDataEncryptionAlgorithms().get(0);
  }

  /** {@inheritDoc} */
  @Override
  public String getKeyTransportEncryptionAlgorithm() {
    return this.systemConfiguration.getKeyTransportEncryptionAlgorithms().get(0);
  }

  /** {@inheritDoc} */
  @Override
  public RSAOAEPParameters getRsaOaepParameters() {
    return new RSAOAEPParameters(
        this.systemConfiguration.getRSAOAEPParameters().getDigestMethod(),
        this.systemConfiguration.getRSAOAEPParameters().getMaskGenerationFunction(),
        this.systemConfiguration.getRSAOAEPParameters().getOAEPParams());
  }

  /**
   * Gets the OpenSAML system configuration.
   *
   * @return OpenSAML encryption configuration
   */
  @JsonIgnore
  public EncryptionConfiguration getSystemConfiguration() {
    return this.systemConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "dataEncryptionAlgorithm='" + this.getDataEncryptionAlgorithm()
        + "', keyTransportEncryptionAlgorithm='" + this.getKeyTransportEncryptionAlgorithm() + "', rsaOaepParameters='"
        + this.getRsaOaepParameters() + "']";
  }

}
