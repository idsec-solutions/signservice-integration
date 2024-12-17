/*
 * Copyright 2019-2024 IDsec Solutions AB
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
package se.idsec.signservice.integration.app.config;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import se.idsec.signservice.integration.config.impl.DefaultIntegrationServiceConfiguration;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Configuration properties for SignService integration.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("signservice")
public class IntegrationServiceConfigurationProperties implements InitializingBean {

  /**
   * The SignService Integration main configuration.
   */
  @Getter
  @Setter
  private DefaultIntegrationServiceConfiguration config;

  /**
   * SignService response settings.
   */
  @Getter
  @Setter
  private ResponseSettings response;

  /**
   * REST settings.
   */
  @Getter
  @Setter
  private RestSettings rest;

  /**
   * The default policy name.
   */
  @Getter
  @Setter
  private String defaultPolicyName;

  /**
   * The credential the service uses for authenticating against the SignService.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties credential;

  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.defaultPolicyName == null) {
      this.defaultPolicyName = "default";
    }
    if (this.response == null) {
      this.response = new ResponseSettings();
    }
    this.response.afterPropertiesSet();
    if (this.rest != null) {
      this.rest.afterPropertiesSet();
    }
  }

  @Data
  @NoArgsConstructor
  public static class RestSettings implements InitializingBean {

    /**
     * Whether REST mode is enabled
     */
    private boolean enabled;

    /**
     * The URL for the REST service.
     */
    private String serverUrl;

    /**
     * The username for authenticating against the REST service.
     */
    private String clientUsername;

    /**
     * The password for authenticating against the REST service.
     */
    private String clientPassword;

    @Override
    public void afterPropertiesSet() throws Exception {
      if (this.enabled) {
        Assert.hasText(this.serverUrl, "signservice.rest.server-url must be set");
        Assert.hasText(this.clientUsername, "signservice.rest.client-username must be set");
        Assert.hasText(this.clientPassword, "signservice.rest.client-password must be set");
      }
    }
  }

  public static class ResponseSettings implements InitializingBean {

    /**
     * Response processing configuration.
     */
    @Getter
    @Setter
    private SignResponseProcessingConfig config;

    @Override
    public void afterPropertiesSet() {
      if (this.config == null) {
        this.config = SignResponseProcessingConfig.defaultSignResponseProcessingConfig();
      }
    }
  }

}
