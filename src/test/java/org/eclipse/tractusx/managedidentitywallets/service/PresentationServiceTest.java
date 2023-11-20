/*
 * *******************************************************************************
 *  Copyright (c) 2021,2023 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.managedidentitywallets.service;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import com.smartsensesolutions.java.commons.specification.SpecificationUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletKeyRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.ssi.lib.crypt.IPrivateKey;
import org.eclipse.tractusx.ssi.lib.crypt.IPublicKey;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.crypt.octet.OctetKeyPairFactory;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559Generator;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559PrivateKey;
import org.eclipse.tractusx.ssi.lib.did.resolver.CompositeDidResolver;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebFactory;
import org.eclipse.tractusx.ssi.lib.did.web.DidWebResolver;
import org.eclipse.tractusx.ssi.lib.did.web.util.DidWebParser;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePrivateKeyFormat;
import org.eclipse.tractusx.ssi.lib.exception.KeyGenerationException;
import org.eclipse.tractusx.ssi.lib.exception.UnsupportedSignatureTypeException;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtFactory;
import org.eclipse.tractusx.ssi.lib.model.MultibaseString;
import org.eclipse.tractusx.ssi.lib.model.base.MultibaseFactory;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.did.DidDocument;
import org.eclipse.tractusx.ssi.lib.model.did.DidDocumentBuilder;
import org.eclipse.tractusx.ssi.lib.model.did.Ed25519VerificationMethod;
import org.eclipse.tractusx.ssi.lib.model.did.Ed25519VerificationMethodBuilder;
import org.eclipse.tractusx.ssi.lib.model.did.VerificationMethod;
import org.eclipse.tractusx.ssi.lib.model.proof.ed21559.Ed25519Signature2020;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialBuilder;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialSubject;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentials;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentation;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentationBuilder;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofGenerator;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.eclipse.tractusx.ssi.lib.serialization.jsonLd.JsonLdSerializerImpl;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedJwtPresentationFactory;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedJwtPresentationFactoryImpl;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedVerifiablePresentation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PresentationServiceTest {

    public static final String BPNL = "BPNL00000000000";

    private static PresentationService presentationService;

    private static HoldersCredentialRepository holdersCredentialRepository;

    private static WalletKeyRepository walletKeyRepository;

    private static CommonService commonService;

    private static WalletKeyService walletKeyService;

    private static MIWSettings miwSettings;

    private static DidDocumentResolverService didDocumentResolverService;

    @RegisterExtension
    static WireMockExtension holder = WireMockExtension.newInstance()
                                                       .options(wireMockConfig()
                                                                        .dynamicPort()
                                                       )
                                                       .build();

    @RegisterExtension
    static WireMockExtension issuer = WireMockExtension.newInstance()
                                                       .options(wireMockConfig()
                                                                        .dynamicPort()
                                                       )
                                                       .build();


    @BeforeAll
    static void beforeAll() {
        miwSettings = Mockito.mock(MIWSettings.class);
        walletKeyService = Mockito.mock(WalletKeyService.class);
        holdersCredentialRepository = Mockito.mock(HoldersCredentialRepository.class);
        commonService = Mockito.mock(CommonService.class);
        walletKeyRepository = Mockito.mock(WalletKeyRepository.class);
        didDocumentResolverService = Mockito.mock(DidDocumentResolverService.class);


        presentationService = new PresentationService(
                holdersCredentialRepository,
                new SpecificationUtil<HoldersCredential>(),
                commonService,
                walletKeyService,
                miwSettings,
                didDocumentResolverService
        );
    }

    @Nested
    class createPresentationTest {

        @Test
        void shouldCreatePresentationAsJWT() {
            Map<String, Object> createPresentationRequest = getCreatePresentationRequest();
            Map<String, Object> stringObjectMap = assertDoesNotThrow(() -> presentationService.createPresentation(
                    createPresentationRequest,
                    true,
                    "audience",
                    "caller"
            ));

            assertTrue(stringObjectMap.containsKey("vp"));
            String vp = (String) stringObjectMap.get("vp");
            assertDoesNotThrow(() -> JWSObject.parse(vp));
        }

        @Test
        void shouldCreatePresentationAsJsonLD() {
            Did issuerDid = DidWebFactory.fromHostname("localhost%3A" + issuer.getPort());
            when(miwSettings.authorityWalletDid()).thenReturn(issuerDid.toUri().toString());

            Map<String, Object> createPresentationRequest = getCreatePresentationRequest();
            Map<String, Object> stringObjectMap = assertDoesNotThrow(() -> presentationService.createPresentation(
                    createPresentationRequest,
                    false,
                    "audience",
                    "caller"
            ));

            assertTrue(stringObjectMap.containsKey("vp"));
            VerifiablePresentation vp = assertDoesNotThrow(() -> (VerifiablePresentation) stringObjectMap.get("vp"));
        }

        private Map<String, Object> getCreatePresentationRequest() {
            Did issuerDid = DidWebFactory.fromHostname("localhost%3A" + issuer.getPort());
            KeyPair issuerKeys = generateKeys();
            KeyPair holderKeys = generateKeys();

            Wallet mockWallet = mockWallet("caller", issuerDid.toUri().toString());
            when(commonService.getWalletByIdentifier("caller")).thenReturn(mockWallet);
            when(walletKeyService.getPrivateKeyByWalletIdentifier(mockWallet.getId())).thenReturn((x21559PrivateKey) holderKeys.getPrivateKey());


            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("VerifiableCredential", "SummaryCredential"),
                    List.of(mockCredentialSubject()),
                    issuerKeys,
                    issuerDid,
                    Instant.now().plus(Duration.ofDays(14))
            );

            Map<String, Object> createPresentationRequest = new HashMap<>();
            createPresentationRequest.put("verifiableCredentials", List.of(verifiableCredential));

            return createPresentationRequest;
        }

        private static Wallet mockWallet(String bpn, String did) {
            Wallet wallet = mock(Wallet.class);
            when(wallet.getId()).thenReturn(new Random().nextLong());
            when(wallet.getName()).thenReturn("WalletName");
            when(wallet.getBpn()).thenReturn(bpn);
            when(wallet.getDid()).thenReturn(did);
            when(wallet.getDidDocument()).thenReturn(null);
            when(wallet.getAlgorithm()).thenReturn("Ed25519");
            when(wallet.getCreatedAt()).thenReturn(new java.util.Date());
            when(wallet.getModifiedAt()).thenReturn(new Date());
            when(wallet.getModifiedFrom()).thenReturn(null);
            return wallet;
        }
    }


    @Nested
    class validatePresentationTest {

        @Test
        void shouldValidate() throws KeyGenerationException, IOException {
            Map<String, Object> vpJwt = validate(Instant.now().plus(Duration.ofDays(5)), "audience", "audience", null);
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, "audience");
            assertTrue((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
            assertTrue((Boolean) result.get("validateAudience"));
        }

        @Test
        void shouldValidateWithoutAudience() throws KeyGenerationException, IOException {
            Map<String, Object> vpJwt = validate(Instant.now().plus(Duration.ofDays(5)), null, null, null);
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, null);
            assertTrue((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
        }

        @Test
        void shouldNotValidateWhenExpired() throws KeyGenerationException, IOException {
            Map<String, Object> vpJwt = validate(Instant.now().minus(Duration.ofDays(2)), "audience", "audience", null);
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, "audience");
            assertFalse((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
            assertTrue((Boolean) result.get("validateAudience"));
        }

        @Test
        void shouldNotValidateWhenLinkedDataValidationFails() throws KeyGenerationException, IOException {
            Map<String, Object> vpJwt = validate(
                    Instant.now().minus(Duration.ofDays(2)),
                    "audience",
                    "audience",
                    generateKeys()
            );
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, "audience");
            assertFalse((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
            assertTrue((Boolean) result.get("validateAudience"));
        }


        @Test
        void shouldNotValidateWhenAudienceMisMatch() throws KeyGenerationException, IOException {
            Map<String, Object> vpJwt = validate(
                    Instant.now().minus(Duration.ofDays(2)),
                    "audience",
                    "audience2",
                    null
            );
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, "audience2");
            assertFalse((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
            assertFalse((Boolean) result.get("validateAudience"));
        }

        @Test
        void shouldThrowWhenSignedJWTValidatorFails() throws KeyGenerationException, IOException {
            HttpClient httpClient = HttpClient.newHttpClient();
            CompositeDidResolver compositeDidResolver = new CompositeDidResolver(new DidWebResolver(
                    httpClient,
                    new DidWebParser(),
                    false
            ));
            Map<String, Object> vpJwt = validate(Instant.now().plus(Duration.ofDays(5)), null, null, null);
            // first throw, then return normally
            when(didDocumentResolverService.getCompositeDidResolver()).thenThrow(RuntimeException.class)
                                                                      .thenReturn(compositeDidResolver);
            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, null);
            assertFalse((Boolean) result.get("valid"));
            assertTrue((Boolean) result.get("validateJWTExpiryDate"));
        }

        @Test
        void shouldThrowWhenNotAsJWT() {
            assertThrows(
                    BadDataException.class,
                    () -> presentationService.validatePresentation(new HashMap<>(), false, true, "")
            );
        }

        @Test
        void shouldNotValidateWhenJwtExpIsExpired() throws KeyGenerationException, IOException {
            HttpClient httpClient = HttpClient.newHttpClient();
            CompositeDidResolver compositeDidResolver = new CompositeDidResolver(new DidWebResolver(
                    httpClient,
                    new DidWebParser(),
                    false
            ));

            when(
                    didDocumentResolverService.getCompositeDidResolver()
            ).thenReturn(compositeDidResolver);


            Did issuerDid = DidWebFactory.fromHostname("localhost%3A" + issuer.getPort());
            Did holderDid = DidWebFactory.fromHostname("localhost%3A" + holder.getPort());
            KeyPair issuerKeys = generateKeys();
            KeyPair holderKeys = generateKeys();

            DidDocument issuerDidDocument = buildDidDocument(
                    issuerDid,
                    issuerKeys,
                    "key-1"
            );
            issuer.stubFor(
                    get("/.well-known/did.json").willReturn(ok(issuerDidDocument.toPrettyJson()))
            );

            // create the holder did document and mock the lookup for validation
            DidDocument holderDidDocument = buildDidDocument(holderDid, holderKeys, "key-1");
            holder.stubFor(
                    get("/.well-known/did.json").willReturn(ok(holderDidDocument.toPrettyJson()))
            );


            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("VerifiableCredential", "SummaryCredential"),
                    List.of(mockCredentialSubject()),
                    issuerKeys,
                    issuerDid,
                    Instant.now().plus(Duration.ofDays(14))
            );
            VerifiablePresentation verifiablePresentation = new VerifiablePresentationBuilder().id(URI.create(holderDid.toString() + "#" + UUID.randomUUID())).type(List.of("VerifiablePresentation")).verifiableCredentials(List.of(verifiableCredential)).build();
            SerializedVerifiablePresentation serializedVerifiablePresentation = new JsonLdSerializerImpl().serializePresentation(verifiablePresentation);

            TestSignedJwtFactory f = new TestSignedJwtFactory(new OctetKeyPairFactory());
            SignedJWT signed = f.create(
                    issuerDid,
                    "audience",
                    serializedVerifiablePresentation,
                    holderKeys.getPrivateKey()
            );

            Map<String, Object> vpJwt = new HashMap<>();
            vpJwt.put("vp", signed.serialize());


            Map<String, Object> result = presentationService.validatePresentation(vpJwt, true, true, null);
            assertFalse((Boolean) result.get("valid"));
            assertFalse((Boolean) result.get("validateJWTExpiryDate"));
        }

        Map<String, Object> validate(
                Instant expirationDate,
                String presentationAudience,
                String inputAudience,
                KeyPair wrongIssuerKeys
        ) throws KeyGenerationException, IOException {
            when(
                    miwSettings.enforceHttps()
            ).thenReturn(false);

            HttpClient httpClient = HttpClient.newHttpClient();
            CompositeDidResolver compositeDidResolver = new CompositeDidResolver(new DidWebResolver(
                    httpClient,
                    new DidWebParser(),
                    false
            ));

            when(
                    didDocumentResolverService.getCompositeDidResolver()
            ).thenReturn(compositeDidResolver);

            // create the issuer did document and mock the lookup for validation
            KeyPair issuerKeys = generateKeys();
            Did issuerDid = DidWebFactory.fromHostname("localhost%3A" + issuer.getPort());
            DidDocument issuerDidDocument = buildDidDocument(
                    issuerDid,
                    wrongIssuerKeys != null ? wrongIssuerKeys : issuerKeys,
                    "key-1"
            );
            issuer.stubFor(
                    get("/.well-known/did.json").willReturn(ok(issuerDidDocument.toPrettyJson()))
            );

            // create the holder did document and mock the lookup for validation
            KeyPair holderKeys = generateKeys();
            Did holderDid = DidWebFactory.fromHostname("localhost%3A" + holder.getPort());
            DidDocument holderDidDocument = buildDidDocument(holderDid, holderKeys, "key-1");
            holder.stubFor(
                    get("/.well-known/did.json").willReturn(ok(holderDidDocument.toPrettyJson()))
            );

            // create the VC from which the VP is created
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("VerifiableCredential", "SummaryCredential"),
                    List.of(mockCredentialSubject()),
                    issuerKeys,
                    issuerDid,
                    expirationDate
            );
            System.out.println(new ObjectMapper().writeValueAsString(verifiableCredential));

            VerifiableCredentials verifiableCredentials = new VerifiableCredentials();
            verifiableCredentials.add(verifiableCredential);
            SignedJWT vp = createPresentation(
                    verifiableCredentials,
                    holderKeys.getPrivateKey(),
                    holderDid,
                    presentationAudience
            );
            Map<String, Object> vpJwt = new HashMap<>();
            vpJwt.put("vp", vp.serialize());

            return vpJwt;
        }

        SignedJWT createPresentation(
                VerifiableCredentials verifiableCredentials,
                IPrivateKey privateKey,
                Did issuer,
                String audience
        ) {
            final SerializedJwtPresentationFactory presentationFactory =
                    new SerializedJwtPresentationFactoryImpl(
                            new SignedJwtFactory(new OctetKeyPairFactory()), new JsonLdSerializerImpl(), issuer);

            return presentationFactory.createPresentation(
                    issuer, verifiableCredentials, audience, privateKey);
        }
    }


    public static DidDocument buildDidDocument(Did did, KeyPair keyPair, String keyId)
            throws KeyGenerationException, IOException {

        // Extracting keys
        // final Ed25519KeySet keySet = new Ed25519KeySet(privateKey, publicKey);

        IPublicKey publicKey = keyPair.getPublicKey();
        final MultibaseString publicKeyBase = MultibaseFactory.create(publicKey.asByte());

        // Building Verification Methods:
        final List<VerificationMethod> verificationMethods = new ArrayList<>();

        final Ed25519VerificationMethodBuilder builder = new Ed25519VerificationMethodBuilder();
        final Ed25519VerificationMethod key =
                builder
                        .id(URI.create(did.toUri() + "#" + keyId))
                        .controller(did.toUri())
                        .publicKeyMultiBase(publicKeyBase)
                        .build();
        verificationMethods.add(key);

        final DidDocumentBuilder didDocumentBuilder = new DidDocumentBuilder();
        didDocumentBuilder.id(did.toUri());
        didDocumentBuilder.verificationMethods(verificationMethods);

        return didDocumentBuilder.build();
    }

    private static VerifiableCredentialSubject mockCredentialSubject() {
        Map<String, Object> subj;
        try (InputStream in = PresentationServiceTest.class.getResourceAsStream("/credential-subject.json")) {
            subj = JSONObjectUtils.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }


        return new VerifiableCredentialSubject(subj);
    }


    private static KeyPair generateKeys() {
        x21559Generator gen = new x21559Generator();
        KeyPair baseWalletKeys;
        try {
            baseWalletKeys = gen.generateKey();
        } catch (KeyGenerationException e) {
            throw new AssertionError(e);
        }
        return baseWalletKeys;
    }

    private static VerifiableCredential mockCredential(
            List<String> types,
            List<VerifiableCredentialSubject> credentialSubjects,
            KeyPair keyPair,
            Did issuer,
            Instant expirationDate
    ) {

        final VerifiableCredentialBuilder builder =
                new VerifiableCredentialBuilder()
                        .context(List.of(
                                         URI.create("https://www.w3.org/2018/credentials/v1"),
                                         URI.create("https://www.w3.org/2018/credentials/examples/v1"),
                                         URI.create("https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json"),
                                         URI.create("https://www.w3.org/ns/odrl.jsonld"),
                                         URI.create("https://w3id.org/security/suites/jws-2020/v1"),
                                         URI.create("https://catenax-ng.github.io/product-core-schemas/SummaryVC.json"),
                                         URI.create("https://w3id.org/security/suites/ed25519-2020/v1")
                                 )
                        )
                        .id(URI.create(issuer + "#key-1"))
                        .issuer(issuer.toUri())
                        .issuanceDate(Instant.now().minus(Duration.ofDays(5)))
                        .credentialSubject(credentialSubjects)
                        .expirationDate(expirationDate)
                        .type(types);


        // Ed25519 Proof Builder
        final LinkedDataProofGenerator generator;
        try {
            generator = LinkedDataProofGenerator.newInstance(SignatureType.ED21559);
        } catch (UnsupportedSignatureTypeException e) {
            throw new AssertionError(e);
        }

        final Ed25519Signature2020 proof;
        try {
            proof = (Ed25519Signature2020)
                    generator.createProof(builder.build(), URI.create(issuer + "#key-1"), keyPair.getPrivateKey());
        } catch (InvalidePrivateKeyFormat e) {
            throw new AssertionError(e);
        }

        // Adding Proof to VC
        builder.proof(proof);

        return builder.build();
    }


    private static VerifiableCredential mockMaliciousCredential(
            List<String> types,
            List<VerifiableCredentialSubject> credentialSubjects,
            KeyPair keyPair,
            Did issuer,
            Instant expirationDate,
            Did maliciousIssuer
    ) {

        final VerifiableCredentialBuilder builder =
                new VerifiableCredentialBuilder()
                        .context(List.of(
                                         URI.create("https://www.w3.org/2018/credentials/v1"),
                                         URI.create("https://www.w3.org/2018/credentials/examples/v1"),
                                         URI.create("https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json"),
                                         URI.create("https://www.w3.org/ns/odrl.jsonld"),
                                         URI.create("https://w3id.org/security/suites/jws-2020/v1"),
                                         URI.create("https://catenax-ng.github.io/product-core-schemas/SummaryVC.json"),
                                         URI.create("https://w3id.org/security/suites/ed25519-2020/v1")
                                 )
                        )
                        .id(URI.create(issuer + "#key-1"))
                        .issuer(issuer.toUri())
                        .issuanceDate(Instant.now().minus(Duration.ofDays(5)))
                        .credentialSubject(credentialSubjects)
                        .expirationDate(expirationDate)
                        .type(types);


        // Ed25519 Proof Builder
        final LinkedDataProofGenerator generator;
        try {
            generator = LinkedDataProofGenerator.newInstance(SignatureType.ED21559);
        } catch (UnsupportedSignatureTypeException e) {
            throw new AssertionError(e);
        }

        final Ed25519Signature2020 proof;
        try {
            proof = (Ed25519Signature2020)
                    generator.createProof(
                            builder.build(),
                            URI.create(maliciousIssuer + "#key-1"),
                            keyPair.getPrivateKey()
                    );
        } catch (InvalidePrivateKeyFormat e) {
            throw new AssertionError(e);
        }

        // Adding Proof to VC
        builder.proof(proof);

        return builder.build();
    }

}
