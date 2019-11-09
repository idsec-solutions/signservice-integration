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
package se.idsec.signservice.integration;

import java.security.KeyStore;

import se.idsec.signservice.integration.saml.IdpEncryptionResolver;

/**
 * Interface that represents the configuration and default settings of a SignService Integration Service
 * policy/instance.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface IntegrationServiceConfiguration {

  /**
   * Returns the integration policy for which this configuration applies.
   * 
   * @return the policy identifier
   */
  String getPolicy();

  /**
   * Returns the default entityID of the entity that requests a signature.
   * <p>
   * This value is used if {@link SignRequestInput#getSignRequesterID()} returns {@code null}.
   * </p>
   * 
   * @return the default sign requester ID
   */
  String getDefaultSignRequesterID();

  /**
   * Returns the default URL to which the user agent along with the sign response message should be directed after a
   * signature operation.
   * <p>
   * This value is used if {@link SignRequestInput#getReturnUrl()} returns {@code null}.
   * </p>
   * 
   * @return the default URL to which a sign response is to be returned
   */
  String getDefaultReturnUrl();

  /**
   * Returns the default algorithm identifier for the signature algorithm that should be used during signing of
   * specified tasks.
   * <p>
   * This value is used if {@link SignRequestInput#getSignatureAlgorithm()} returns {@code null}.
   * </p>
   * 
   * @return signature algorithm identifier
   */
  String getDefaultSignatureAlgorithm();

  /**
   * Returns the entityID of the signature service. This ID is the SAML entityID of the SAML Service Provider that is
   * running in the signature service.
   * 
   * @return the ID of the signature service
   */
  String getSignServiceID();

  /**
   * Returns the default signature service URL to where {@code dss:SignRequest} messages should be posted.
   * 
   * @return the default destination URL of the signature service to where sign messages should be posted
   */
  String getDefaultDestinationUrl();

  IdpEncryptionResolver getIdpEncryptionResolver();

  /* KeyStore */ void getIntegrationServiceSigningCredentials();

  /**
   * Tells whether the SignService Integration Service is running in stateless mode or not.
   * <p>
   * A SignService Integration Service may execute in a stateless mode, meaning that it does not keep a session state
   * and leaves it up to the caller to maintain the state between calls to
   * {@link SignServiceIntegrationService#createSignRequest(SignRequestInput)} and
   * {@link SignServiceIntegrationService#processSignResponse(String, SignatureState, SignResponseProcessingParameters)},
   * or it may execute in a stateful mode, meaning that it keeps the necessary data between calls to
   * {@link SignServiceIntegrationService#createSignRequest(SignRequestInput)} and
   * {@link SignServiceIntegrationService#processSignResponse(String, SignatureState, SignResponseProcessingParameters)}
   * and the only thing the caller needs to keep track of its the ID of the signature operation (see
   * {@link SignatureState#getId()}.
   * </p>
   * 
   * @return if the SignService Integration Service is running in stateless mode {@code true} is returned, otherwise
   *         {@code false}
   * @see SignatureState
   */
  boolean isStateless();

  // Caching
}
