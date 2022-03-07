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
package se.idsec.signservice.integration.core.validation;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.integration.core.error.InputValidationException;
import se.idsec.signservice.integration.core.impl.CorrelationID;

/**
 * Abstract implementation of an input validator.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractInputValidator<T, H> implements InputValidator<T, H> {

  /** {@inheritDoc} */
  @Override
  public void validateObject(final T object, final String objectName, final H hint) throws InputValidationException {
    if (objectName == null) {
      throw new InputValidationException("unknown", "Bad call to validateObject");
    }
    ValidationResult errors = this.validate(object, objectName, hint);
    if (errors.hasErrors()) {
      log.error("{}: Validation error: {}", CorrelationID.id(), errors);
      if (errors.getGlobalError() != null) {
        throw new InputValidationException(errors.getObjectName(), errors.getGlobalError(), errors.getFieldErrors());
      }
      else {
        throw new InputValidationException(errors.getObjectName(), errors.getFieldErrors());
      }
    }
  }

}
