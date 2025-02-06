public class Tools
{
    public string GenerateSamlResponse()
    {
        var guidToUse = Guid.NewGuid();
        var responseDestionation = "";
        var issuerUrl = "";
        var userId = "";
        var certificate = "";
        var certificateForEncryption = "";

        var assertion = CreateAssertionXml(guidToUse,responseDestionation,issuerUrl, userId, DateTime.UtcNow + TimeSpan.FromMinutes(2));

        ///sign assertion
        SignXmlWCertificate(guidToUse, assertion, certificate);

        /// encrypted Assertion
        var encryptedAssertion = Encrypt(assertion.OwnerDocument.DocumentElement, certificateForEncryption);

        ///Generate Response and Insert 
        var samlResponse = CreateSamlResponseXml(guidToUse, responseDestionation, issuerUrl, encryptedAssertion);

        ///sign saml response
        SignXmlWCertificate(guidToUse, samlResponse, certificate);

        var base64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(samlResponse.OuterXml.ToString()));
        return base64;
    }

    public static XmlElement CreateAssertionXml(Guid guidToUse, string destination, string issuer, string userId, DateTime tokenExpiry)
    {
        const string prefix = "saml";
        const string ns = "urn:oasis:names:tc:SAML:2.0:assertion";

        XmlDocument assertion = new XmlDocument();
        XmlElement assertionElement = assertion.CreateElement(prefix, "Assertion", ns);
        assertionElement.SetAttribute("Version", "2.0");
        assertionElement.SetAttribute("ID", "_" + guidToUse);
        assertionElement.SetAttribute("IssueInstant", DateTime.UtcNow.ToString("o"));

        ///Issuer
        assertionElement.AppendChild(CreateIssuer(assertion, prefix, ns, issuer));

        ///Subject
        XmlElement subjectElement = assertion.CreateElement(prefix, "Subject", ns);

        XmlElement nameIdElement = assertion.CreateElement(prefix, "NameID", ns);
        nameIdElement.InnerText = userId;
        subjectElement.AppendChild(nameIdElement);

        XmlElement subjectConfirmationElement = assertion.CreateElement(prefix, "SubjectConfirmation", ns);
        subjectConfirmationElement.SetAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");

        XmlElement subjectConfirmationDataElement = assertion.CreateElement(prefix, "SubjectConfirmationData", ns);
        subjectConfirmationDataElement.SetAttribute("Recipient", destination);

        subjectConfirmationElement.AppendChild(subjectConfirmationDataElement);
        subjectElement.AppendChild(subjectConfirmationElement);

        assertionElement.AppendChild(subjectElement);


        ///Conditions
        XmlElement conditionsElement = assertion.CreateElement(prefix, "Conditions", ns);
        conditionsElement.SetAttribute("NotOnOrAfter", tokenExpiry.ToString("o"));

        XmlElement audienceRestrictionElement = assertion.CreateElement(prefix, "AudienceRestriction", ns);

        XmlElement audienceElement = assertion.CreateElement(prefix, "Audience", ns);
        audienceElement.InnerText = destination;
        audienceRestrictionElement.AppendChild(audienceElement);
        conditionsElement.AppendChild(audienceRestrictionElement);

        assertionElement.AppendChild(conditionsElement);

        ///AuthnStatement
        XmlElement authStatementElement = assertion.CreateElement(prefix, "AuthnStatement", ns);
        authStatementElement.SetAttribute("AuthnInstant", DateTime.UtcNow.ToString("o"));

        XmlElement authContextElement = assertion.CreateElement(prefix, "AuthnContext", ns);
        XmlElement authContextClassRefElement = assertion.CreateElement(prefix, "AuthnContextClassRef", ns);
        authContextClassRefElement.InnerText = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
        authContextElement.AppendChild(authContextClassRefElement);

        authStatementElement.AppendChild(authContextElement);

        assertionElement.AppendChild(authStatementElement);

        assertion.AppendChild(assertionElement);
        return assertion.DocumentElement;
    }

    private static XmlElement CreateIssuer(XmlDocument document, string prefix, string ns, string value)
    {
        XmlElement issuerElement = document.CreateElement(prefix, "Issuer", ns);
        issuerElement.InnerText = value;
        return issuerElement;
    }

    public static void SignXmlWCertificate(Guid guidToUse, XmlElement xml, X509Certificate2 certificate)
    {
        SignedXml signedXml = new SignedXml(xml);
        signedXml.SigningKey = certificate.GetRSAPrivateKey();
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

        string uri = string.Concat("#", "_", guidToUse.ToString());
        Reference reference = new Reference(uri);
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform("#default samlp saml ds xs xsi"));
        reference.DigestMethod = SignedXml.XmlDsigSHA1Url;
        signedXml.AddReference(reference);

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));

        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        XmlElement xmlsig = signedXml.GetXml();

        xml.AppendChild(xmlsig);
    }

    public static XmlElement Encrypt(XmlElement assertion, X509Certificate2 cert)
    {
        /// create symmetric key
        var symmetricAlgorithm = Aes.Create() as SymmetricAlgorithm;
        symmetricAlgorithm.KeySize = 256;

        ///Create class Encrypted Key to generate XML
        EncryptedKey encriptedKey = new EncryptedKey()
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url)
        };

        ///Obtain cipher data to EncriptedKey
        encriptedKey.CipherData.CipherValue = EncryptedXml.EncryptKey(symmetricAlgorithm.Key, cert.GetRSAPublicKey(), false);

        ///Create class Encrypted Data to generate XML
        EncryptedData encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
        };

        ///Add key info encrypted to encrypted data
        KeyInfoEncryptedKey clause = new KeyInfoEncryptedKey(encriptedKey);
        encryptedData.KeyInfo.AddClause(clause);

        EncryptedXml eXml = new EncryptedXml();
        encryptedData.CipherData.CipherValue = eXml.EncryptData(Encoding.UTF8.GetBytes(assertion.OuterXml), symmetricAlgorithm);

        XmlDocument encryptedAssertion = new XmlDocument();

        /// Add name spaces Structure
        XmlDeclaration xmlDeclaration = encryptedAssertion.CreateXmlDeclaration("1.0", "UTF-8", null);
        XmlElement encryptedRoot = encryptedAssertion.DocumentElement;
        encryptedAssertion.InsertBefore(xmlDeclaration, encryptedRoot);

        ///Create Xml Of Encrypted Assertion
        XmlElement encryptedAssertionElement = encryptedAssertion.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encryptedAssertion.AppendChild(encryptedAssertionElement);

        ///import node to xml document created
        var encryptedDataNode = encryptedAssertion.ImportNode(encryptedData.GetXml(), true);

        /// Add Encrypted Data inside of Encrypted Assertion
        encryptedAssertionElement.AppendChild(encryptedDataNode);

        return encryptedAssertion.DocumentElement;
    }

    public static XmlElement CreateSamlResponseXml(Guid guidToUse, string destination, string issuer, XmlElement encryptedAssertion)
    {
        const string prefix = "samlp";
        const string ns = "urn:oasis:names:tc:SAML:2.0:protocol";

        XmlDocument response = new XmlDocument();
        XmlElement responseElement = response.CreateElement(prefix, "Response", ns);
        responseElement.SetAttribute("ID", "_" + guidToUse);
        responseElement.SetAttribute("Version", "2.0");
        responseElement.SetAttribute("IssueInstant", DateTime.UtcNow.ToString("o"));
        responseElement.SetAttribute("Destination", destination);

        ///Issuer
        responseElement.AppendChild(CreateIssuer(response, "saml", "urn:oasis:names:tc:SAML:2.0:assertion", issuer));

        ///Status
        XmlElement statusElement = response.CreateElement(prefix,"Status", ns);
        XmlElement statusCodeElement = response.CreateElement(prefix, "StatusCode", ns);
        statusCodeElement.SetAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
        statusElement.AppendChild(statusCodeElement);

        responseElement.AppendChild(statusElement);

        var encryptedAssertionNode = response.ImportNode(encryptedAssertion, true);
        responseElement.AppendChild(encryptedAssertionNode);

        response.AppendChild(responseElement);
        return response.DocumentElement;
    }
}
        