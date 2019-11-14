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

/**
 * An interface for a resolver that returns the Identity Provider encryption information to be used when the SignService
 * Integration Service performs encryption of a sign message (intended to be displayed by the SAML Identity Provider).
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@FunctionalInterface
public interface IdpEncryptionResolver {

  /**
   * Given the SAML entityID of the Identity Provider the method finds the encryption parameters (certificate/key and
   * algorithms) to be used when encrypting a sign message for an Identity Provider.
   * 
   * @param entityID
   *          the SAML entityID for the Identity Provider
   * @return the IdP encryption parameters
   * @throws Exception
   *           if no encryption parameters can be resolved
   */
  IdpEncryptionParameters resolveIdpEncryptionParameters(String entityID) throws Exception;

  // TODO: declare exception
}
