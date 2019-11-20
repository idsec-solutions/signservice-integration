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
package se.idsec.signservice.integration.config.impl;

import java.security.cert.X509Certificate;

import org.opensaml.security.x509.X509Credential;

import net.shibboleth.utilities.java.support.logic.Constraint;
import se.idsec.signservice.integration.config.SigningCredential;

/**
 * A {@code SigningCredential} implementation backed by a OpenSAML {@link X509Credential} object.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OpenSAMLSigningCredential implements SigningCredential {

  /** The OpenSAML credential. */
  private X509Credential credential;

  /**
   * Constructor.
   * 
   * @param credential
   *          the credential
   */
  public OpenSAMLSigningCredential(final X509Credential credential) {
    this.credential = Constraint.isNotNull(credential, "credential must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public X509Certificate getSigningCertificate() {
    return this.credential.getEntityCertificate();
  }

}
