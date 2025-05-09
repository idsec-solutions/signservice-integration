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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration for SignService Integration policies provided in separate file.
 *
 * @author Martin Lindström
 */
@Configuration
@PropertySource(ignoreResourceNotFound = true,
    value = "${signservice.integration.policy-configuration-resource}",
    factory = CustomPropertySourceFactory.class)
public class PolicyConfiguration implements InitializingBean {

  /**
   * SignService Integration policy configuration.
   */
  @Getter
  @Setter
  private Map<String, PolicyConfigurationProperties> config = new HashMap<>();

  @Bean("SignService.External.Policies")
  Map<String, PolicyConfigurationProperties> externalPolicyConfiguration() {
    return Optional.ofNullable(this.config).orElse(new HashMap<>());
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    if (this.config != null) {
      for (final Map.Entry<String, PolicyConfigurationProperties> e : this.config.entrySet()) {
        e.getValue().afterPropertiesSet();
      }
    }
  }

}
