/*
 * Copyright 2019 IDsec Solutions AB
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

import java.util.Arrays;
import java.util.Base64;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import se.idsec.signservice.integration.authentication.SignerIdentityAttribute;
import se.idsec.signservice.integration.certificate.CertificateAttributeMapping;
import se.idsec.signservice.integration.certificate.CertificateType;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttribute;
import se.idsec.signservice.integration.certificate.RequestedCertificateAttributeType;
import se.idsec.signservice.integration.certificate.SigningCertificateRequirements;
import se.idsec.signservice.integration.document.pdf.PdfSignatureImageTemplate;
import se.idsec.signservice.integration.security.impl.EncryptionParametersImpl;

public class DefaultIntegrationServiceConfigurationTest {

  @Test
  public void toJson() throws Exception {
    
    DefaultIntegrationServiceConfiguration config = DefaultIntegrationServiceConfiguration.builder()
      .policy("default")
      .defaultSignRequesterID("http://demo.idsec.se")
      .defaultReturnUrl("https://demo.idsec.se/signresponse")
      .defaultSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      .signServiceID("http://sign.service.com")
      .defaultDestinationUrl("https://sign.service.com/req")
      .signingCertificateRequirements(
        SigningCertificateRequirements.builder()
          .certificateType(CertificateType.PKC)
          .attributeMappings(Arrays.asList(
            CertificateAttributeMapping.builder()
              .source(SignerIdentityAttribute.createBuilder()
                .type(SignerIdentityAttribute.SAML_TYPE)
                .name("urn:oid:1.2.752.29.4.13")
                .build())
              .destination(RequestedCertificateAttribute.builder()
                .type(RequestedCertificateAttributeType.RDN)
                .name("2.5.4.5")
                .friendlyName("serialNumber")
                .required(true)
                .build())
              .build(),
            CertificateAttributeMapping.builder()
              .source(SignerIdentityAttribute.createBuilder().name("urn:oid:2.5.4.6").build())
              .destination(RequestedCertificateAttribute.builder()
                .type(RequestedCertificateAttributeType.RDN)
                .name("urn:oid:2.5.4.6")
                .friendlyName("country")
                .required(true)
                .defaultValue("SE")
                .build())
              .build()))
          .build())
      .pdfSignatureImageTemplate(PdfSignatureImageTemplate.builder()
        .reference("companylogo")
        .image(Base64.getEncoder().encodeToString("mumbojumbo".getBytes()))
        .width(300)
        .height(300)
        .includeSignerName(true)
        .includeSigningTime(true)
        .field("reason", "The reason/purpose of the signature")
        .field(PdfSignatureImageTemplate.SIGNER_NAME_FIELD_NAME, "The signer name")
        .field(PdfSignatureImageTemplate.SIGNING_TIME_FIELD_NAME, "The time the signature was created")
        .build())
      .stateless(true)
      .defaultEncryptionParameters(EncryptionParametersImpl.builder().build())
      .signingCredentials(
        new KeyStoreSigningCredential(new ClassPathResource("signing.jks"), "secret".toCharArray(), "default"))
      .build();
    
    ObjectMapper mapper = new ObjectMapper();
    mapper.setSerializationInclusion(Include.NON_NULL);
    ObjectWriter writer = mapper.writerWithDefaultPrettyPrinter();

    String json = writer.writeValueAsString(config);

    System.out.println(json);
    
  }

}
