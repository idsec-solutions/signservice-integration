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

/**
 * An interface defining the sign message parameters.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface SignMessageParameters {

  /**
   * Gets the (non-encrypted) sign message (non encrypted) content according to specified mime type.
   * 
   * @return the sign message
   */
  String getSignMessage();

  /**
   * Tells whether the supplied sign message should be encrypted with {@link #getDisplayEntity()} as the recipient.
   * 
   * @return tells whether encryption should be performed
   */
  boolean isPerformEncryption();

  /**
   * Gets the sign message MIME type.
   * 
   * @return the MIME type, or {@code null} which defaults to {@link SignMessageMimeType#TEXT}.
   */
  SignMessageMimeType getMimeType();

  /**
   * Specifies if the requester of the signature requires that the sign message is displayed to the user. If the
   * Identity Provider cannot fulfill this requirement it must not proceed.
   * 
   * @return the MustShow flag
   */
  boolean isMustShow();

  /**
   * Gets the SAML entityID of the entity (IdP) that should display this message.
   * 
   * <p>
   * Note: The {@code DisplayEntity} attribute of the {@code SignMessage} element is required if the sign message is to
   * be encrypted. In almost all cases, except for some odd Proxy-IdP cases, this is the same value as
   * {@link SignRequestInput#getAuthnServiceID()}. Therefore, if this method returns {@code null}, and the
   * message should be encrypted, the SignService Integration Service will use the
   * {@link SignRequestInput#getAuthnServiceID()} value.
   * </p>
   * 
   * @return the entityID of the IdP that should display the message
   */
  String getDisplayEntity();

}
