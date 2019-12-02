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

import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

/**
 * Validator for {@link DefaultIntegrationServiceConfiguration}.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DefaultIntegrationServiceConfigurationValidator implements Validator {

  /** {@inheritDoc} */
  @Override
  public boolean supports(Class<?> clazz) {
    return DefaultIntegrationServiceConfiguration.class.equals(clazz);
  }

  /** {@inheritDoc} */
  @Override
  public void validate(Object target, Errors errors) {
    DefaultIntegrationServiceConfiguration config = (DefaultIntegrationServiceConfiguration) target;
    
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, "policy", "config-error.missing-policy");
    
    // TODO
  }

}
