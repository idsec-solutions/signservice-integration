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

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import se.idsec.signservice.integration.process.SignResponseProcessingConfig;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for setting up a SignService Integration Service.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("signservice")
public class IntegrationServiceConfigurationProperties implements InitializingBean {

  /**
   * SignService response processing configuration.
   */
  @Getter
  @NestedConfigurationProperty
  private final SignResponseProcessingConfig response = new SignResponseProcessingConfig();

  /**
   * Name for the default policy.
   */
  @Getter
  @Setter
  private String defaultPolicyName;

  /**
   * SignService Integration policy configuration.
   */
  @Getter
  @NestedConfigurationProperty
  private final Map<String, PolicyConfigurationProperties> config = new HashMap<>();

  @Override
  public void afterPropertiesSet() throws Exception {
    this.response.init();
    for (final Map.Entry<String, PolicyConfigurationProperties> e : this.config.entrySet()) {
      e.getValue().afterPropertiesSet();
    }
  }

}
