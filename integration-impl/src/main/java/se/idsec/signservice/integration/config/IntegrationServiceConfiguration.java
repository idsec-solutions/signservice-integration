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
package se.idsec.signservice.integration.config;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nonnull;

import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.idsec.signservice.security.sign.SigningCredential;

/**
 * Interface that represents the configuration settings of a SignService Integration Service policy/instance.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IntegrationServiceConfiguration extends IntegrationServiceDefaultConfiguration {

  /**
   * Gets the signing credential that the SignService Integration Service policy instance uses to sign SignRequest
   * messages.
   * 
   * @return the signing credential for the SignService Integration Service policy
   */
  @Nonnull
  SigningCredential getSigningCredential();

  /**
   * See {@link #getSignServiceCertificates()}.
   * 
   * @return the signature service signing certificate(s)
   */
  @Nonnull
  List<X509Certificate> getSignServiceCertificatesInternal();

  /**
   * See {@link #getTrustAnchors()}.
   * 
   * @return the SignService CA root certificate(s)
   */
  @Nonnull
  List<X509Certificate> getTrustAnchorsInternal();

  /**
   * If the SignService Integration Service is running as a server we don't want to expose sensitive data such as
   * signing keys and such in the {@link SignServiceIntegrationService#getConfiguration(String)} method. Therefore, this
   * method makes sure to only deliver the "public" configuration.
   * 
   * @return an IntegrationServiceDefaultConfiguration instance
   */
  @Nonnull
  IntegrationServiceDefaultConfiguration getPublicConfiguration();

}
