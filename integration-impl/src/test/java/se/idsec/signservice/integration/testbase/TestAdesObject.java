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
package se.idsec.signservice.integration.testbase;

import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;

public class TestAdesObject implements AdesObject {

  private final AdesSigningCertificateDigest certDigest;

  public TestAdesObject(final AdesSigningCertificateDigest certDigest) {
    this.certDigest = certDigest;
  }

  @Override
  public AdesSigningCertificateDigest getSigningCertificateDigest() {
    return this.certDigest;
  }
  
}
