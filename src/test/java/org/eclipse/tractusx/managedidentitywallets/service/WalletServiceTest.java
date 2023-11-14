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

import com.nimbusds.jose.util.JSONObjectUtils;
import com.smartsensesolutions.java.commons.specification.SpecificationUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.exception.ForbiddenException;
import org.eclipse.tractusx.managedidentitywallets.utils.EncryptionUtils;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559Generator;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePrivateKeyFormat;
import org.eclipse.tractusx.ssi.lib.exception.KeyGenerationException;
import org.eclipse.tractusx.ssi.lib.exception.UnsupportedSignatureTypeException;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethod;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethodIdentifier;
import org.eclipse.tractusx.ssi.lib.model.proof.ed21559.Ed25519Signature2020;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialBuilder;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialSubject;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofGenerator;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.orm.hibernate5.HibernateTransactionManager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class WalletServiceTest {

    public static final String DID_WEB_LOCALHOST = "did:web:localhost";

    private static WalletRepository walletRepository;

    private static MIWSettings miwSettings;

    private static EncryptionUtils encryptionUtils;

    private static WalletKeyService walletKeyService;

    private static HoldersCredentialRepository holdersCredentialRepository;

    private static SpecificationUtil<Wallet> walletSpecificationUtil;

    private static IssuersCredentialService issuersCredentialService;

    private static CommonService commonService;

    private static WalletService walletService;

    @BeforeAll
    public static void beforeAll() {
        walletRepository = Mockito.mock(WalletRepository.class);
        miwSettings = Mockito.mock(MIWSettings.class);
        encryptionUtils = Mockito.mock(EncryptionUtils.class);
        walletKeyService = Mockito.mock(WalletKeyService.class);
        holdersCredentialRepository = Mockito.mock(HoldersCredentialRepository.class);
        walletSpecificationUtil = new SpecificationUtil<Wallet>();
        issuersCredentialService = Mockito.mock(IssuersCredentialService.class);
        commonService = Mockito.mock(CommonService.class);


        walletService = new WalletService(
                walletRepository,
                miwSettings,
                encryptionUtils,
                walletKeyService,
                holdersCredentialRepository,
                walletSpecificationUtil,
                issuersCredentialService,
                commonService,
                new HibernateTransactionManager()
        );
    }

    @BeforeEach
    public void beforeEach() {
        Mockito.reset(
                walletRepository,
                miwSettings,
                encryptionUtils,
                walletKeyService,
                holdersCredentialRepository,
                issuersCredentialService,
                commonService
        );
    }

    @Nested
    class getWalletByIdentifierTest {

        @Test
        void shouldReturnWalletWithCredentials() {
            String bpn = "bpn";
            VerifiableCredential verifiableCredential = mockCredential(List.of(
                    "VerifiableCredential",
                    "LegalParticipant"
            ));


            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);

            // because service returns the !!!entity!!! from the database, the real method has to be called
            doCallRealMethod().when(wallet).setVerifiableCredentials(any(List.class));
            doCallRealMethod().when(wallet).getVerifiableCredentials();
            // end of wtf

            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);
            when(holdersCredentialRepository.getCredentialsByHolder(wallet.getDid())).thenReturn(List.of(
                    verifiableCredential));
            when(miwSettings.authorityWalletBpn()).thenReturn(bpn);


            Wallet returnedWallet = assertDoesNotThrow(() -> walletService.getWalletByIdentifier(
                    "identifier",
                    true,
                    bpn
            ));
            assertNotNull(returnedWallet);
            assertEquals(DID_WEB_LOCALHOST, returnedWallet.getDid());
            assertFalse(returnedWallet.getVerifiableCredentials().isEmpty());
        }

        @Test
        void shouldReturnWalletWithoutCredentials() {
            String bpn = "bpn";
            VerifiableCredential verifiableCredential = mockCredential(List.of(
                    "VerifiableCredential",
                    "LegalParticipant"
            ));


            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);

            // because service returns the !!!entity!!! from the database, the real method has to be called
            doCallRealMethod().when(wallet).setVerifiableCredentials(any(List.class));
            doCallRealMethod().when(wallet).getVerifiableCredentials();
            // end of wtf

            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);
            when(holdersCredentialRepository.getCredentialsByHolder(wallet.getDid())).thenReturn(List.of(
                    verifiableCredential));
            when(miwSettings.authorityWalletBpn()).thenReturn(bpn);


            Wallet returnedWallet = assertDoesNotThrow(() -> walletService.getWalletByIdentifier(
                    "identifier",
                    false,
                    bpn
            ));
            assertNotNull(returnedWallet);
            assertEquals(DID_WEB_LOCALHOST, returnedWallet.getDid());
            assertNull(returnedWallet.getVerifiableCredentials());
        }

        // authorityWalletBpn != callerBpn
        // walletBpn != callerBpn
        @Test
        void shouldThrowWhenCallerBPNDoesNotMatchWalletAndAuthorityWallet() {
            String bpn = "bpn";
            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);
            when(miwSettings.authorityWalletBpn()).thenReturn("1234");
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);
            ForbiddenException identifier = assertThrows(
                    ForbiddenException.class,
                    () -> walletService.getWalletByIdentifier(
                            "identifier",
                            false,
                            "4321"
                    )
            );
        }

        // authorityWalletBpn != callerBpn
        // walletBpn == callerBpn
        @Test
        void shouldThrowWhenBPNDoesNotMatch() {
            String bpn = "bpn";
            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);
            when(miwSettings.authorityWalletBpn()).thenReturn("1234");
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);
            assertDoesNotThrow(() -> walletService.getWalletByIdentifier(
                                       "identifier",
                                       false,
                                       bpn
                               )
            );
        }
    }

    @Nested
    class storeCredentialTest {

        @Test
        void shouldStoreCredential() {
            String bpn = "bpn";
            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            Map<String, String> message = assertDoesNotThrow(() -> walletService.storeCredential(
                    mockCredential(List.of("VerifiableCredential", "LegalParticipant")),
                    "identifier",
                    bpn
            ));
            assertNotNull(message);
        }

        @Test
        void shouldNotStoreCredentialWhenNoBPNMatched() {
            String bpn = "bpn";
            Wallet wallet = mockWallet("123", DID_WEB_LOCALHOST);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            assertThrows(ForbiddenException.class, () -> walletService.storeCredential(
                    mockCredential(List.of("VerifiableCredential", "LegalParticipant")),
                    "identifier",
                    bpn
            ));
        }

        @Test
        void shouldNotStoreCredentialWhenNoTypesContained() {
            String bpn = "bpn";
            Wallet wallet = mockWallet(bpn, DID_WEB_LOCALHOST);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            assertThrows(BadDataException.class, () -> walletService.storeCredential(
                    mockCredential(Collections.emptyList()),
                    "identifier",
                    bpn
            ));
        }
    }

    private static Wallet mockWallet(String bpn, String did) {
        Wallet wallet = mock(Wallet.class);
        when(wallet.getId()).thenReturn(null);
        when(wallet.getName()).thenReturn(null);
        when(wallet.getBpn()).thenReturn(bpn);
        when(wallet.getDid()).thenReturn(did);
        when(wallet.getDidDocument()).thenReturn(null);
        when(wallet.getAlgorithm()).thenReturn("Ed25519");
        when(wallet.getCreatedAt()).thenReturn(new Date());
        when(wallet.getModifiedAt()).thenReturn(new Date());
        when(wallet.getModifiedFrom()).thenReturn(null);
        return wallet;
    }

    private static VerifiableCredential mockCredential(List<String> types) {

        Did issuer = new Did(new DidMethod("web"), new DidMethodIdentifier("localhost"), null);
        final VerifiableCredentialBuilder builder =
                new VerifiableCredentialBuilder()
                        .context(List.of(
                                URI.create("https://www.w3.org/2018/credentials/v1"),
                                URI.create(
                                        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#")
                        ))
                        .id(URI.create(issuer + "#key-1"))
                        .issuer(issuer.toUri())
                        .issuanceDate(Instant.now())
                        .credentialSubject(mockCredentialSubject())
                        .expirationDate(Instant.now().plus(Duration.ofDays(5)))
                        .type(types);

        // Ed25519 Proof Builder
        final LinkedDataProofGenerator generator;
        try {
            generator = LinkedDataProofGenerator.newInstance(SignatureType.ED21559);
        } catch (UnsupportedSignatureTypeException e) {
            throw new AssertionError(e);
        }

        x21559Generator gen = new x21559Generator();
        KeyPair keyPair;
        try {
            keyPair = gen.generateKey();
        } catch (KeyGenerationException e) {
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


    private static VerifiableCredentialSubject mockCredentialSubject() {
        Map<String, Object> subj;
        try (InputStream in = WalletServiceTest.class.getResourceAsStream("/credential-subject.json")) {
            subj = JSONObjectUtils.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }


        return new VerifiableCredentialSubject(subj);
    }


}
