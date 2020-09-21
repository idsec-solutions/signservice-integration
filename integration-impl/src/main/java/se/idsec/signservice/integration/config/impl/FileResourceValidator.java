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
package se.idsec.signservice.integration.config.impl;

import se.idsec.signservice.integration.core.FileResource;
import se.idsec.signservice.integration.core.validation.AbstractInputValidator;
import se.idsec.signservice.integration.core.validation.ValidationResult;

/**
 * Validator for {@link FileResource} objects.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class FileResourceValidator extends AbstractInputValidator<FileResource, Void> {

  /** {@inheritDoc} */
  @Override
  public ValidationResult validate(final FileResource object, final String objectName, final Void hint) {
    final ValidationResult result = new ValidationResult(objectName);
    if (object == null) {
      return result;
    }

    try {
      if (object.getContents() == null) {
        result.rejectValue("contents", "Missing contents for FileResource");
      }
    }
    catch (Exception e) {
      result.rejectValue("contents", "Failed to read contents for FileResource - " + e.getMessage());
    }

    return result;
  }

}
