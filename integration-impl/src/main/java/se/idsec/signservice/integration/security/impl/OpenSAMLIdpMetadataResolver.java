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

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.core.impl.CorrelationID;
import se.idsec.signservice.integration.security.IdpMetadataResolver;
import se.idsec.signservice.integration.security.MetadataException;

/**
 * Implementation of the {@link IdpMetadataResolver} interface using an OpenSAML {@link MetadataResolver}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class OpenSAMLIdpMetadataResolver implements IdpMetadataResolver {

  /** The metadata resolver. */
  private final MetadataResolver metadataResolver;

  /**
   * Constructor.
   *
   * @param metadataResolver
   *          the metadata resolver
   */
  public OpenSAMLIdpMetadataResolver(final MetadataResolver metadataResolver) {
    this.metadataResolver = metadataResolver;
  }

  /** {@inheritDoc} */
  @Override
  public EntityDescriptor resolveMetadata(final String entityID, final IntegrationServiceConfiguration config) throws MetadataException {
    try {
      final CriteriaSet criteria = new CriteriaSet();
      criteria.add(new EntityIdCriterion(entityID));
      final EntityDescriptor metadata = this.metadataResolver.resolveSingle(criteria);
      if (metadata == null) {
        final String msg = String.format("Metadata for '%s' could not be found", entityID);
        log.error("{}:{}", CorrelationID.id(), msg);
        throw new MetadataException(msg);
      }
      return metadata;
    }
    catch (final ResolverException e) {
      final String msg = String.format("Error during download of metadata for '%s' - %s", entityID, e.getMessage());
      log.error("{}:{}", CorrelationID.id(), msg, e);
      throw new MetadataException(msg, e);
    }
  }

}
