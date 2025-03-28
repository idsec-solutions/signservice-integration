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
package se.idsec.signservice.integration.document.xml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import se.idsec.signservice.xml.DOMUtils;

import java.io.InputStream;

/**
 * Test cases for XadesQualifyingProperties.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class XadesQualifyingPropertiesTest {

  @Test
  public void testDecode() throws Exception {
    try (final InputStream is = this.getClass().getClassLoader().getResourceAsStream("ds-object.xml")) {
      final Element dsObjectElement = DOMUtils.inputStreamToDocument(is).getDocumentElement();
      final XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties(dsObjectElement);
      Assertions.assertNotNull(xqp.getSigningCertificateDigest());
      Assertions.assertNotNull(xqp.getSigningTime());
    }
  }

  @Test
  public void testAssignSignaturePolicy() throws Exception {
    final XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties();
    xqp.setSignaturePolicy("1.2.3.4.5");
    Assertions.assertNotNull(xqp.getSignaturePolicyIdentifier());
    Assertions.assertEquals("1.2.3.4.5",
        xqp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
            .getIdentifier().getValue());
  }

  @Test
  public void testAssignSignaturePolicyToObject() throws Exception {
    try (final InputStream is = this.getClass().getClassLoader().getResourceAsStream("ds-object.xml")) {
      final Element dsObjectElement = DOMUtils.inputStreamToDocument(is).getDocumentElement();

      final XadesQualifyingProperties xqp = XadesQualifyingProperties.createXadesQualifyingProperties(dsObjectElement);

      xqp.setSignaturePolicy("1.2.3.4.5");
      Assertions.assertNotNull(xqp.getSignaturePolicyIdentifier());
      Assertions.assertEquals("1.2.3.4.5",
          xqp.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
              .getIdentifier().getValue());

      // Assert that updating works
      final Element element = xqp.getAdesElement();
      final XadesQualifyingProperties xqp2 = XadesQualifyingProperties.createXadesQualifyingProperties(element);
      Assertions.assertNotNull(xqp2.getSignaturePolicyIdentifier());
      Assertions.assertEquals("1.2.3.4.5",
          xqp2.getSignaturePolicyIdentifier().getSignaturePolicyId().getSigPolicyId()
              .getIdentifier().getValue());
    }
  }

}
