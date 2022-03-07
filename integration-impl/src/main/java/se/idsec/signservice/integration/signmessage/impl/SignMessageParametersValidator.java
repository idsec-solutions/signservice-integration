/*
 * Copyright 2019-2022 IDsec Solutions AB
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
package se.idsec.signservice.integration.signmessage.impl;

import org.apache.commons.lang.StringUtils;

import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;
import se.idsec.signservice.integration.signmessage.SignMessageMimeType;
import se.idsec.signservice.integration.signmessage.SignMessageParameters;

/**
 * Validator for {@link SignMessageParameters} objects.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignMessageParametersValidator extends AbstractInputValidator<SignMessageParameters, Void> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final SignMessageParameters object, final String objectName, final Void hint) {

    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }
    if (StringUtils.isBlank(object.getSignMessage())) {
      result.rejectValue("signMessage", "Missing sign message");
    }
    if (object.getMimeType() != null) {
      try {
        SignMessageMimeType.fromMimeType(object.getMimeType());
      }
      catch (final IllegalArgumentException e) {
        result.rejectValue("mimeType", e.getMessage());
      }
    }
    return result;
  }

}
