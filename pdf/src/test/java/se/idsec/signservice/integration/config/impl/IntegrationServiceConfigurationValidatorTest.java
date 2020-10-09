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

import java.lang.reflect.Field;

import org.junit.Assert;
import org.junit.Test;

import se.idsec.signservice.integration.document.pdf.signpage.impl.ExtendedPdfSignaturePageValidator;

/**
 * Tests for loading of IntegrationServiceConfigurationValidator.
 * <p>
 * The IntegrationServiceConfigurationValidator loads the ExtendedPdfSignaturePageValidator if it is in the classpath.
 * This test verifies that this is done.
 * </p>
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class IntegrationServiceConfigurationValidatorTest {

  @Test 
  public void testLoad() throws Exception {
    IntegrationServiceConfigurationValidator validator = new IntegrationServiceConfigurationValidator();

    Field field = validator.getClass().getDeclaredField("pdfSignaturePageValidator");
    field.setAccessible(true);
    Object object = field.get(validator);
    Assert.assertTrue(ExtendedPdfSignaturePageValidator.class.isInstance(object));
  }

}
