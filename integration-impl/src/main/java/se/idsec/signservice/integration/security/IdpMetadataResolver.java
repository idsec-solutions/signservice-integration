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
package se.idsec.signservice.integration.security;

import jakarta.annotation.Nonnull;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;

/**
 * Interface used by the SignService Integration Service to obtain SAML metadata for an IdP before the encryption
 * process.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@FunctionalInterface
public interface IdpMetadataResolver {

  /**
   * Gets the (valid) metadata for the given SAML IdP.
   *
   * @param entityID the entityID for the IdP
   * @param config policy configuration
   * @return the IdP metadata
   * @throws MetadataException if no valid metadata can be found, or any other error occur
   */
  EntityDescriptor resolveMetadata(@Nonnull final String entityID,
      @Nonnull final IntegrationServiceConfiguration config) throws MetadataException;

}
