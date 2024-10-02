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
package se.idsec.signservice.integration.config;

import se.idsec.signservice.integration.SignServiceIntegrationService;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.cert.X509Certificate;
import java.util.List;

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
  PkiCredential getSigningCredential();

  /**
   * See {@link #getSignServiceCertificates()}.
   *
   * @return the signature service signing certificate(s)
   */
  List<X509Certificate> getSignServiceCertificatesInternal();

  /**
   * See {@link #getTrustAnchors()}.
   *
   * @return the SignService CA root certificate(s)
   */
  List<X509Certificate> getTrustAnchorsInternal();

  /**
   * If the SignService Integration Service is running as a server we don't want to expose sensitive data such as
   * signing keys and such in the {@link SignServiceIntegrationService#getConfiguration(String)} method. Therefore, this
   * method makes sure to only deliver the "public" configuration.
   *
   * @return an IntegrationServiceDefaultConfiguration instance
   */
  IntegrationServiceDefaultConfiguration getPublicConfiguration();

  /**
   * If several policies are created where most settings are the same, the {@code parentPolicy} can be used to inherit
   * values from. In this way, only the values that should be overridden needs to be supplied.
   *
   * @return the policy to inherit from, or null
   * @see #mergeConfiguration(IntegrationServiceConfiguration)
   */
  String getParentPolicy();

  /**
   * If {@link #getParentPolicy()} is set, this method is used to merge the parent policy configuration into this
   * object. After the merge has been performed the parent policy is unset.
   *
   * @param parent the policy to merge from
   */
  void mergeConfiguration(final IntegrationServiceConfiguration parent);

}
