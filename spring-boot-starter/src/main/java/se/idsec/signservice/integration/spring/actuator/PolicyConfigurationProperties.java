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
package se.idsec.signservice.integration.spring.actuator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import se.idsec.signservice.integration.config.IntegrationServiceConfiguration;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;

import java.io.Serial;

/**
 * Configuration properties for a SignService integration policy.
 *
 * @author Martin Lindström
 */
@NoArgsConstructor
@AllArgsConstructor
public class PolicyConfigurationProperties extends DefaultIntegrationServiceConfiguration implements InitializingBean {

  @Serial
  private static final long serialVersionUID = 2833577213650041909L;

  /**
   * Configuration for the signing credential that the SignService Integration Service policy instance uses to sign
   * SignRequest messages.
   */
  @Getter
  @Setter
  @JsonIgnore
  private transient PkiCredentialConfigurationProperties signingCredentialConfig;

  @Override
  public void mergeConfiguration(final IntegrationServiceConfiguration parent) {
    if (!parent.getPolicy().equals(this.getParentPolicy())) {
      throw new IllegalArgumentException("Invalid policy merge");
    }
    if (parent instanceof final PolicyConfigurationProperties parentPolicy) {
      if (this.signingCredentialConfig == null && this.getSigningCredential() == null) {
        this.signingCredentialConfig = parentPolicy.signingCredentialConfig;
      }
    }
    super.mergeConfiguration(parent);
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.getSigningCredential() != null && this.signingCredentialConfig != null) {
      throw new IllegalArgumentException("signing-credential and signing-credential-config can not both be given");
    }
  }

  @Override
  public String toString() {
    return super.toString();
  }

}
