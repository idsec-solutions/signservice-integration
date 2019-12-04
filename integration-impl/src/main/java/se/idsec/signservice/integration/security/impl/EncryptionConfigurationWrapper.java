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
package se.idsec.signservice.integration.security.impl;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.KeyTransportAlgorithmPredicate;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;

import com.google.common.collect.ImmutableList;

import se.idsec.signservice.integration.security.EncryptionParameters;
import se.swedenconnect.opensaml.xmlsec.ExtendedEncryptionConfiguration;
import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ConcatKDFParameters;

/**
 * A wrapper for OpenSAML's system configuration for encryption parameters that puts the policy default configuration
 * first.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EncryptionConfigurationWrapper implements ExtendedEncryptionConfiguration {

  /** The default encryption parameters for a given SignService Intergration policy. */
  private final EncryptionParameters defaultEncryptionParameters;

  /** The OpenSAML system encryption configuration. */
  private final EncryptionConfiguration systemConfiguration;
  
  /** Don't ask. */
  private ExtendedEncryptionConfiguration extendedSystemConfiguration;

  /** Data encryption algorithms. */
  private List<String> dataEncryptionAlgorithms;

  /** Key transport encryption algorithms. */
  private List<String> keyTransportEncryptionAlgorithms;

  /**
   * Constructor.
   * 
   * @param defaultEncryptionParameters
   *          the default encryption parameters for a given SignService Integration policy
   */
  public EncryptionConfigurationWrapper(final EncryptionParameters defaultEncryptionParameters) {
    this.defaultEncryptionParameters = defaultEncryptionParameters;
    this.systemConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
    if (!ExtendedEncryptionConfiguration.class.isInstance(this.systemConfiguration)) {
      this.extendedSystemConfiguration = ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration();
    }
  }

  /** {@inheritDoc} */
  @Override
  public Collection<String> getWhitelistedAlgorithms() {
    return this.systemConfiguration.getWhitelistedAlgorithms();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isWhitelistMerge() {
    return this.systemConfiguration.isWhitelistMerge();
  }

  /** {@inheritDoc} */
  @Override
  public Collection<String> getBlacklistedAlgorithms() {
    return this.systemConfiguration.getBlacklistedAlgorithms();
  }

  /** {@inheritDoc} */
  @Override
  public boolean isBlacklistMerge() {
    return this.systemConfiguration.isBlacklistMerge();
  }

  /** {@inheritDoc} */
  @Override
  public Precedence getWhitelistBlacklistPrecedence() {
    return this.systemConfiguration.getWhitelistBlacklistPrecedence();
  }

  /** {@inheritDoc} */
  @Override
  public List<Credential> getDataEncryptionCredentials() {
    return this.systemConfiguration.getDataEncryptionCredentials();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getDataEncryptionAlgorithms() {
    if (this.dataEncryptionAlgorithms == null) {
      List<String> _dataEncryptionAlgorithms = new LinkedList<>(this.systemConfiguration.getDataEncryptionAlgorithms());
      int index = _dataEncryptionAlgorithms.indexOf(this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      if (index < 0) {
        _dataEncryptionAlgorithms.add(0, this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      }
      else if (index > 0) {
        _dataEncryptionAlgorithms.remove(index);
        _dataEncryptionAlgorithms.add(0, this.defaultEncryptionParameters.getDataEncryptionAlgorithm());
      }
      this.dataEncryptionAlgorithms = _dataEncryptionAlgorithms;
    }
    return ImmutableList.copyOf(this.dataEncryptionAlgorithms);
  }

  /** {@inheritDoc} */
  @Override
  public List<Credential> getKeyTransportEncryptionCredentials() {
    return this.systemConfiguration.getKeyTransportEncryptionCredentials();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getKeyTransportEncryptionAlgorithms() {
    if (this.keyTransportEncryptionAlgorithms == null) {
      List<String> _keyTransportEncryptionAlgorithms = new LinkedList<>(this.systemConfiguration.getKeyTransportEncryptionAlgorithms());
      int index = _keyTransportEncryptionAlgorithms.indexOf(this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      if (index < 0) {
        _keyTransportEncryptionAlgorithms.add(0, this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      }
      else if (index > 0) {
        _keyTransportEncryptionAlgorithms.remove(index);
        _keyTransportEncryptionAlgorithms.add(0, this.defaultEncryptionParameters.getKeyTransportEncryptionAlgorithm());
      }
      this.dataEncryptionAlgorithms = _keyTransportEncryptionAlgorithms;      
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
  @Override
  public List<Credential> getKeyAgreementCredentials() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getAgreementMethodAlgorithms() {
    if (this.extendedSystemConfiguration != null) {
      return this.extendedSystemConfiguration.getAgreementMethodAlgorithms();
    }
    else {
      return ((ExtendedEncryptionConfiguration) this.systemConfiguration).getAgreementMethodAlgorithms();
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getKeyDerivationAlgorithms() {
    if (this.extendedSystemConfiguration != null) {
      return this.extendedSystemConfiguration.getKeyDerivationAlgorithms();
    }
    else {
      return ((ExtendedEncryptionConfiguration) this.systemConfiguration).getKeyDerivationAlgorithms();
    }
  }

  /** {@inheritDoc} */
  @Override
  public ConcatKDFParameters getConcatKDFParameters() {
    if (this.extendedSystemConfiguration != null) {
      return this.extendedSystemConfiguration.getConcatKDFParameters();
    }
    else {
      return ((ExtendedEncryptionConfiguration) this.systemConfiguration).getConcatKDFParameters();
    }
  }

}
