/*
 * Copyright 2019-2025 IDsec Solutions AB
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

import jakarta.annotation.Nonnull;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.io.Resource;
import se.idsec.signservice.security.certificate.CertificateUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * For Spring Framework users. A {@link Converter} that gets the property value (e.g., {@code classpath:cert.crt}) and
 * instantiates a {@link X509Certificate} onbject.
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
 * public PropertyToX509CertificateConverter propertyToX509CertificateConverter() {
 *   return new PropertyToX509CertificateConverter();
 * }
 * </pre>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PropertyToX509CertificateConverter implements Converter<String, X509Certificate>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** {@inheritDoc} */
  @Override
  public X509Certificate convert(@Nonnull final String source) {

    final Resource resource = this.applicationContext.getResource(source);

    try {
      return CertificateUtils.decodeCertificate(resource.getInputStream());
    }
    catch (final CertificateException | IOException e) {
      throw new IllegalArgumentException(String.format("Failed to convert %s to a X509Certificate", source));
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(@Nonnull final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

}
