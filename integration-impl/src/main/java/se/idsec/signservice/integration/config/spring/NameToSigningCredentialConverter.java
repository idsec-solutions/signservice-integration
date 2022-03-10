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
package se.idsec.signservice.integration.config.spring;

import java.util.Map;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * For Spring Framework users. A {@link Converter} that lets the user reference a {@link PkiCredential} instance
 * using its bean name, or if no bean is found, the signing credential name (@link {@link PkiCredential#getName()}.
 * <p>
 * To use this converter it has to be instantiated as a bean and then registered in the registry using
 * {@link ConverterRegistry#addConverter(Converter)}.
 * </p>
 * <p>
 * If you are using Spring Boot, do:
 * </p>
 * <pre>
 * &#64;Bean
 * &#64;ConfigurationPropertiesBinding
 * public NameToSigningCredentialConverter nameToSigningCredentialConverter() {
 *   return new NameToSigningCredentialConverter();
 * }
 * </pre>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class NameToSigningCredentialConverter implements Converter<String, PkiCredential>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** {@inheritDoc} */
  @Override
  public PkiCredential convert(final String source) {
    if (source == null || !StringUtils.hasText(source)) {
      return null;
    }
    log.debug("Converting '{}' into a PkiCredential instance ...", source);
    try {
      final PkiCredential cred = this.applicationContext.getBean(source, PkiCredential.class);
      log.debug("Found bean of type '{}' and bean name '{}' in the application context", PkiCredential.class.getSimpleName(), source);
      return cred;
    }
    catch (final BeansException e) {
      log.debug("No bean of type '{}' and bean name '{}' has been registered", PkiCredential.class.getSimpleName(), source);
    }
    log.debug("Listing all PkiCredential beans ...");
    try {
      final Map<String, PkiCredential> map = this.applicationContext.getBeansOfType(PkiCredential.class);
      for (final PkiCredential c : map.values()) {
        if (source.equalsIgnoreCase(c.getName())) {
          log.debug("Found bean of type '{}' and given name '{}' in the application context",
            PkiCredential.class.getSimpleName(), source);
          return c;
        }
      }
    }
    catch (final BeansException e) {
    }
    final String msg = String.format("No SigningCredential instance matching '%s' was found", source);
    log.error("%s", msg);
    throw new IllegalArgumentException(msg);
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
