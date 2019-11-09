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

import java.util.List;

import se.idsec.signservice.integration.attributes.IdentityAttributeValue;

/**
 * A sign requester specifies a set of authentication requirements regarding the signer when sending a
 * {@code SignRequest} message. This interface represents these requirements.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface AuthnRequirements {

  /**
   * Returns the entityID of the authentication service (Identity Provider) that will authenticate the signer as part of
   * the signature process.
   * <p>
   * In almost all cases a user is first authenticated before performing a signature, and the entityID is then the ID of
   * the Identity Provider that authenticated the user during login to the service requesting the signature.
   * </p>
   * <p>
   * In the rare cases where a user is not authenticated when the signature is requested, it is the signature
   * requester's responsibility to prompt the user for the authentication service to use, or by other means acquire this
   * information.
   * </p>
   * 
   * @return the entityID of the authentication service to use
   */
  String getAuthnServiceID();

  /**
   * Returns the authentication context reference identifier (an URI) that identifies the context under which the signer
   * should be authenticated. This identifier is often referred to as the "level of assurance" (LoA).
   * <p>
   * In the normal case where the user already has been authenticated, the authentication context reference identifier
   * received from the authentication process should be used.
   * </p>
   * 
   * @return the authentication context reference URI
   */
  String getAuthnContextRef();

  /**
   * Returns a list of identity attributes that the sign requestor requires the authentication service (IdP) to validate
   * and deliver (and the signature service to assert).
   * 
   * <p>
   * Typically, a sign requester includes the identity attributes that binds the signature operation to the principal
   * that authenticated at the sign requester service, for example the personalIdentityNumber of the principal.
   * </p>
   * 
   * @return a list of requested attribute values
   */
  List<IdentityAttributeValue> getRequestedSignerAttributes();

}
