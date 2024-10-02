/*
 * Copyright 2019-2023 IDsec Solutions AB
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

import com.google.common.collect.ImmutableList;
import jakarta.annotation.Nonnull;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.KeyTransportAlgorithmPredicate;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.encryption.support.KeyAgreementEncryptionConfiguration;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import se.idsec.signservice.integration.security.EncryptionParameters;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * A wrapper for OpenSAML's system configuration for encryption parameters that puts the policy default configuration
 * first.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EncryptionConfigurationWrapper implements EncryptionConfiguration {

  /** The default encryption parameters for a given SignService Intergration policy. */
  private final EncryptionParameters defaultEncryptionParameters;

  /** The OpenSAML system encryption configuration. */
  private final EncryptionConfiguration systemConfiguration;

  /** Data encryption algorithms. */
  private List<String> dataEncryptionAlgorithms;

  /** Key transport encryption algorithms. */
  private List<String> keyTransportEncryptionAlgorithms;

  /**
   * Constructor.
   *
   * @param defaultEncryptionParameters the default encryption parameters for a given SignService Integration
   *     policy
   */
  public EncryptionConfigurationWrapper(final EncryptionParameters defaultEncryptionParameters) {
    this.defaultEncryptionParameters = defaultEncryptionParameters;
    this.systemConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<Credential> getDataEncryptionCredentials() {
    return this.systemConfiguration.getDataEncryptionCredentials();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<String> getDataEncryptionAlgorithms() {
    if (this.dataEncryptionAlgorithms == null) {
      final List<String> _dataEncryptionAlgorithms =
          new LinkedList<>(this.systemConfiguration.getDataEncryptionAlgorithms());
      final int index =
          _dataEncryptionAlgorithms.indexOf(this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      if (index < 0) {
        _dataEncryptionAlgorithms.addFirst(this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      }
      else if (index > 0) {
        _dataEncryptionAlgorithms.remove(index);
        _dataEncryptionAlgorithms.addFirst(this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      }
      this.dataEncryptionAlgorithms = _dataEncryptionAlgorithms;
    }
    return ImmutableList.copyOf(this.dataEncryptionAlgorithms);
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<Credential> getKeyTransportEncryptionCredentials() {
    return this.systemConfiguration.getKeyTransportEncryptionCredentials();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public List<String> getKeyTransportEncryptionAlgorithms() {
    if (this.keyTransportEncryptionAlgorithms == null) {
      final List<String> _keyTransportEncryptionAlgorithms =
          new LinkedList<>(this.systemConfiguration.getKeyTransportEncryptionAlgorithms());
      final int index = _keyTransportEncryptionAlgorithms
          .indexOf(this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      if (index < 0) {
        _keyTransportEncryptionAlgorithms.addFirst(
            this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      }
      else if (index > 0) {
        _keyTransportEncryptionAlgorithms.remove(index);
        _keyTransportEncryptionAlgorithms.addFirst(
            this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      }
      this.keyTransportEncryptionAlgorithms = _keyTransportEncryptionAlgorithms;
    }
    return ImmutableList.copyOf(this.keyTransportEncryptionAlgorithms);
  }

  /** {@inheritDoc} */
  @Override
  public NamedKeyInfoGeneratorManager getDataKeyInfoGeneratorManager() {
    return this.systemConfiguration.getDataKeyInfoGeneratorManager();
  }

  /** {@inheritDoc} */
  @Override
  public NamedKeyInfoGeneratorManager getKeyTransportKeyInfoGeneratorManager() {
    return this.systemConfiguration.getKeyTransportKeyInfoGeneratorManager();
  }

  /** {@inheritDoc} */
  @Override
  public RSAOAEPParameters getRSAOAEPParameters() {
    return new RSAOAEPParameters(
        this.defaultEncryptionParameters.getRsaOaepParameters().getDigestMethod(),
        this.defaultEncryptionParameters.getRsaOaepParameters().getMaskGenerationFunction(),
        this.defaultEncryptionParameters.getRsaOaepParameters().getOaepParams());
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRSAOAEPParametersMerge() {
    return this.systemConfiguration.isRSAOAEPParametersMerge();
  }

  /** {@inheritDoc} */
  @Override
  public KeyTransportAlgorithmPredicate getKeyTransportAlgorithmPredicate() {
    return this.systemConfiguration.getKeyTransportAlgorithmPredicate();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Map<String, KeyAgreementEncryptionConfiguration> getKeyAgreementConfigurations() {
    return this.systemConfiguration.getKeyAgreementConfigurations();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Collection<String> getIncludedAlgorithms() {
    return this.systemConfiguration.getIncludedAlgorithms();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isIncludeMerge() {
    return this.systemConfiguration.isIncludeMerge();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public Collection<String> getExcludedAlgorithms() {
    return this.systemConfiguration.getExcludedAlgorithms();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isExcludeMerge() {
    return this.systemConfiguration.isExcludeMerge();
  }

  /** {@inheritDoc} */
  @Nonnull
  @Override
  public org.opensaml.xmlsec.AlgorithmPolicyConfiguration.Precedence getIncludeExcludePrecedence() {
    return this.systemConfiguration.getIncludeExcludePrecedence();
  }

}
