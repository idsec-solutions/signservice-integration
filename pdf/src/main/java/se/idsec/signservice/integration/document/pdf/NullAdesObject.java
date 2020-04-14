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
package se.idsec.signservice.integration.document.pdf;

import se.idsec.signservice.integration.document.ades.AdesObject;
import se.idsec.signservice.integration.document.ades.AdesSigningCertificateDigest;

/**
 * Null AdesObject for PDF signing. This maps to the AdesObject in the SignTaskData structure.
 * These objects are used in XML to carry signed attributes such as signed certificate hash.
 * These objects are however never used in PDF signing where all signed attributes are placed within CMS
 * SignedAttributes.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NullAdesObject implements AdesObject {
  

  /** This method always returns null. Signed signing certificate digest is found in CMS signed attributes */
  @Override
  public AdesSigningCertificateDigest getSigningCertificateDigest() {
    return null;
  }

}
