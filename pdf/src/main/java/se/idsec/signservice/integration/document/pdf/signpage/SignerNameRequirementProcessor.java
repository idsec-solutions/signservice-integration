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
package se.idsec.signservice.integration.document.pdf.signpage;

import se.idsec.signservice.integration.authentication.SignerIdentityAttributeValue;

import java.util.List;

public interface SignerNameRequirementProcessor {

  /**
   * Get the attribute requirements for including a name in the visible sign image
   * @param signerAttrlist list of name attributes included in the sign request representing the signer identity
   *
   *                       <p>Signer name attributes must be among these attributes</p>
   * @return signer name requirements
   */
  SignerNameRequirement getSignerNameRequirements(List<SignerIdentityAttributeValue> signerAttrlist);

}
