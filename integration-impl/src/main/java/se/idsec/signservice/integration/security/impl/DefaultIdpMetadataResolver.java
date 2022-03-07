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
package se.idsec.signservice.integration.security.impl;

import java.util.Optional;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.security.IdpMetadataResolver;
import se.idsec.signservice.integration.security.MetadataException;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;

/**
 * Default implementation of the {@link IdpMetadataResolver}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultIdpMetadataResolver implements IdpMetadataResolver {

  /** The metadata provider. */
  private final MetadataProvider metadataProvider;

  /**
   * Constructor.
   *
   * @param metadataProvider
   *          the metadata provider from where metadata is obtained
   */
  public DefaultIdpMetadataResolver(final MetadataProvider metadataProvider) {
    this.metadataProvider = metadataProvider;
  }

  /** {@inheritDoc} */
  @Override
  public EntityDescriptor resolveMetadata(final String entityID, final IntegrationServiceConfiguration config) throws MetadataException {
    try {
      return Optional.ofNullable(this.metadataProvider.getEntityDescriptor(entityID))
        .orElseThrow(() -> new MetadataException(String.format("Metadata for '%s' could not be found", entityID)));
    }
    catch (final ResolverException e) {
      final String msg = String.format("Error during download of metadata for '%s' - %s", entityID, e.getMessage());
      log.error("{}:{}", CorrelationID.id(), msg, e);
      throw new MetadataException(msg, e);
    }
  }

}
