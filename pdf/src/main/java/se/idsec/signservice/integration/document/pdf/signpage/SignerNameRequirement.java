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
package se.idsec.signservice.integration.document.pdf.signpage;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;

/**
 * Holds the signer name requirements for a PDF sign image.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignerNameRequirement {

  /**
   * List of name attributes included in the sign request representing the signer identity. Signer name attributes must
   * be among these attributes.
   *
   * @param signerNameAttributeList name attributes included in the sign request representing the signer identity
   * @return name attributes included in the sign request representing the signer identity
   */
  private List<SignerIdentityAttribute> signerNameAttributeList;

  /**
   * The format string determining the formatting of the signer name in the visible sign image.
   * <p>
   * Example "%1 %2 (%3)" causes the result "AttributeVal-1 AttriubteVal-2 (AttributeVal-3)".
   * </p>
   *
   * @param formatString the format string determining the formatting of the signer name in the visible sign image.
   * @return the format string determining the formatting of the signer name in the visible sign image, or null
   */
  private String formatString;
}
