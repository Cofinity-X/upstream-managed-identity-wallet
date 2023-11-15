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
import java.sql.Connection;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import javax.sql.DataSource;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.constant.MIWVerifiableCredentialType;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.IssuersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.IssuersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueDismantlerCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueFrameworkCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.dto.IssueMembershipCredentialRequest;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.exception.ForbiddenException;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559Generator;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePrivateKeyFormat;
import org.eclipse.tractusx.ssi.lib.exception.KeyGenerationException;
import org.eclipse.tractusx.ssi.lib.exception.UnsupportedSignatureTypeException;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.did.DidDocument;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethod;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethodIdentifier;
import org.eclipse.tractusx.ssi.lib.model.did.VerificationMethod;
import org.eclipse.tractusx.ssi.lib.model.proof.ed21559.Ed25519Signature2020;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialBuilder;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialSubject;
import org.eclipse.tractusx.ssi.lib.proof.LinkedDataProofGenerator;
import org.eclipse.tractusx.ssi.lib.proof.SignatureType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IssuersCredentialServiceTest {

    public static final String DID_WEB_LOCALHOST = "did:web:localhost";

    private static MIWSettings miwSettings;


    private static WalletKeyService walletKeyService;

    private static HoldersCredentialRepository holdersCredentialRepository;

    private static CommonService commonService;

    private static IssuersCredentialRepository issuersCredentialRepository;

    private static IssuersCredentialService issuersCredentialService;

    @BeforeAll
    public static void beforeAll() throws SQLException {
        miwSettings = Mockito.mock(MIWSettings.class);
        walletKeyService = Mockito.mock(WalletKeyService.class);
        holdersCredentialRepository = Mockito.mock(HoldersCredentialRepository.class);
        commonService = Mockito.mock(CommonService.class);
        issuersCredentialRepository = mock(IssuersCredentialRepository.class);

        Connection connection = mock(Connection.class);

        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);


        issuersCredentialService = new IssuersCredentialService(
                issuersCredentialRepository,
                miwSettings,
                new SpecificationUtil<IssuersCredential>(),
                walletKeyService,
                holdersCredentialRepository,
                commonService
        );
    }

    @BeforeEach
    public void beforeEach() {
        Mockito.reset(
                miwSettings,
                walletKeyService,
                holdersCredentialRepository,
                commonService,
                issuersCredentialRepository
        );
    }

    @Nested
    class issueMembershipCredential{
        @Test
        void shouldIssueCredential(){
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            KeyPair keyPair = generateKeys();

            when(miwSettings.contractTemplatesUrl()).thenReturn("https://templates.com");
            when(miwSettings.authorityWalletBpn()).thenReturn(baseWalletBpn);
            when(commonService.getWalletByIdentifier(baseWalletBpn)).thenReturn(baseWallet);
            when(commonService.getWalletByIdentifier(holderWalletBpn)).thenReturn(holderWallet);
            when(walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(baseWallet.getId()))
                    .thenReturn(keyPair.getPrivateKey().asByte());
            when(miwSettings.supportedFrameworkVCTypes()).thenReturn(Set.of("SustainabilityCredential"));
            when(miwSettings.vcExpiryDate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(2))));
            when(holdersCredentialRepository.save(any(HoldersCredential.class)))
                    .thenAnswer(new Answer<HoldersCredential>() {
                                    @Override
                                    public HoldersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        HoldersCredential argument = invocation.getArgument(0, HoldersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );

            // make the filter bs work
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            // make inline update work: issuersCredential = create(issuersCredential); bs
            when(issuersCredentialRepository.save(any(IssuersCredential.class)))
                    .thenAnswer(new Answer<IssuersCredential>() {
                                    @Override
                                    public IssuersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        IssuersCredential argument = invocation.getArgument(0, IssuersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );


            IssueMembershipCredentialRequest issueMembershipCredentialRequest = new IssueMembershipCredentialRequest();
            issueMembershipCredentialRequest.setBpn(holderWalletBpn);

            assertDoesNotThrow(() -> issuersCredentialService.issueMembershipCredential(issueMembershipCredentialRequest, baseWalletBpn));

        }
    }

    @Nested
    class issueDismantlerCredential{

        @Test
        void shouldThrowWhenbaseWalletBpnIsNotCallerBpn(){
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            when(miwSettings.authorityWalletBpn()).thenReturn(baseWalletBpn);
            when(commonService.getWalletByIdentifier(baseWalletBpn)).thenReturn(baseWallet);
            when(commonService.getWalletByIdentifier(holderWalletBpn)).thenReturn(holderWallet);

            IssueDismantlerCredentialRequest request = new IssueDismantlerCredentialRequest();
            request.setActivityType("dunno");
            request.setBpn(holderWalletBpn);
            request.setAllowedVehicleBrands(Collections.emptySet());

            assertThrows(ForbiddenException.class, () -> issuersCredentialService.issueDismantlerCredential(request, "1234"));
        }

        @Test
        void shouldIssueCredential(){
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            KeyPair keyPair = generateKeys();

            when(miwSettings.contractTemplatesUrl()).thenReturn("https://templates.com");
            when(miwSettings.authorityWalletBpn()).thenReturn(baseWalletBpn);
            when(commonService.getWalletByIdentifier(baseWalletBpn)).thenReturn(baseWallet);
            when(commonService.getWalletByIdentifier(holderWalletBpn)).thenReturn(holderWallet);
            when(walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(baseWallet.getId()))
                    .thenReturn(keyPair.getPrivateKey().asByte());
            when(miwSettings.supportedFrameworkVCTypes()).thenReturn(Set.of("SustainabilityCredential"));
            when(miwSettings.vcExpiryDate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(2))));
            when(holdersCredentialRepository.save(any(HoldersCredential.class)))
                    .thenAnswer(new Answer<HoldersCredential>() {
                                    @Override
                                    public HoldersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        HoldersCredential argument = invocation.getArgument(0, HoldersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );


            // make the filter bs work
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            // make inline update work: issuersCredential = create(issuersCredential); bs
            when(issuersCredentialRepository.save(any(IssuersCredential.class)))
                    .thenAnswer(new Answer<IssuersCredential>() {
                                    @Override
                                    public IssuersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        IssuersCredential argument = invocation.getArgument(0, IssuersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );

            IssueDismantlerCredentialRequest request = new IssueDismantlerCredentialRequest();
            request.setActivityType("dunno");
            request.setBpn(holderWalletBpn);
            request.setAllowedVehicleBrands(Collections.emptySet());

            assertDoesNotThrow(() -> issuersCredentialService.issueDismantlerCredential(request, baseWalletBpn));
        }
    }

    @Nested
    class issueFrameWorkCredentialTest {

        @Test
        void shouldFailWhenTypeNotSupported(){
            when(miwSettings.supportedFrameworkVCTypes()).thenReturn(Set.of("SustainabilityCredential"));
            IssueFrameworkCredentialRequest request = new IssueFrameworkCredentialRequest();
            request.setType("type");

            assertThrows(BadDataException.class, () -> issuersCredentialService.issueFrameworkCredential(request, "12345"));
        }

        @Test
        void shouldIssueCredential() {
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            KeyPair keyPair = generateKeys();

            when(miwSettings.contractTemplatesUrl()).thenReturn("https://templates.com");
            when(miwSettings.authorityWalletBpn()).thenReturn(baseWalletBpn);
            when(commonService.getWalletByIdentifier(baseWalletBpn)).thenReturn(baseWallet);
            when(commonService.getWalletByIdentifier(holderWalletBpn)).thenReturn(holderWallet);
            when(walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(baseWallet.getId()))
                    .thenReturn(keyPair.getPrivateKey().asByte());
            when(miwSettings.supportedFrameworkVCTypes()).thenReturn(Set.of("SustainabilityCredential"));
            when(miwSettings.vcExpiryDate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(2))));
            when(holdersCredentialRepository.save(any(HoldersCredential.class)))
                    .thenAnswer(new Answer<HoldersCredential>() {
                                    @Override
                                    public HoldersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        HoldersCredential argument = invocation.getArgument(0, HoldersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            when(issuersCredentialRepository.save(any(IssuersCredential.class)))
                    .thenAnswer(new Answer<IssuersCredential>() {
                                    @Override
                                    public IssuersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        IssuersCredential argument = invocation.getArgument(0, IssuersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );

            HoldersCredential holdersCredential = mock(HoldersCredential.class);

            when(holdersCredentialRepository.getByHolderDidAndIssuerDidAndTypeAndStored(
                    any(String.class),
                    any(String.class),
                    eq(MIWVerifiableCredentialType.SUMMARY_CREDENTIAL),
                    eq(false)
            )).thenReturn(List.of(holdersCredential, holdersCredential, holdersCredential));


            IssueFrameworkCredentialRequest request = TestUtils.getIssueFrameworkCredentialRequest(
                    holderWalletBpn,
                    "SustainabilityCredential"
            );

            assertDoesNotThrow(() -> issuersCredentialService.issueFrameworkCredential(request, baseWalletBpn));

        }
    }

    @Nested
    class issueBpnCredentialTest {
        // test empty credential subject for IssuerCredential
        // test credential subject list > 1 for IssuerCredential

        @Test
        void shouldIssueBpnCredentialWithAuthorityFalse() {
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            shouldIssueBpnCredential(baseWallet, holderWallet);
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            assertDoesNotThrow(() -> issuersCredentialService.issueBpnCredential(baseWallet, holderWallet, false));
        }

        @Test
        void shouldIssueWhenFilterEmpty() {
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            shouldIssueBpnCredential(baseWallet, holderWallet);
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(Collections.emptyList())
            );

            assertDoesNotThrow(() -> issuersCredentialService.issueBpnCredential(baseWallet, holderWallet, false));
        }

        @Test
        void shouldThrowWhenMorThanOneCredentialSubject() {
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            shouldIssueBpnCredential(baseWallet, holderWallet);
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(
                            mockCredentialSubject(),
                            mockCredentialSubject()
                    )
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            assertThrows(
                    BadDataException.class,
                    () -> issuersCredentialService.issueBpnCredential(baseWallet, holderWallet, false)
            );
        }

        @Test
        void shouldIssueWhenHolderCredentialIsNotEmpty() {
            String baseWalletBpn = TestUtils.getRandomBpmNumber();
            List<VerificationMethod> verificationMethod = mockVerificationMethod();
            DidDocument baseWalletDidDocument = mockDidDocument();
            baseWalletDidDocument.put("verificationMethod", verificationMethod);
            Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
            when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
            String holderWalletBpn = TestUtils.getRandomBpmNumber();
            Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

            shouldIssueBpnCredential(baseWallet, holderWallet);
            VerifiableCredential verifiableCredential = mockCredential(
                    List.of("TypeA,TypeB"),
                    List.of(mockCredentialSubject())
            );
            IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);
            //getRepository().findAll(specification, pageRequest);
            when(issuersCredentialRepository.findAll(any(Specification.class), any(PageRequest.class))).thenReturn(
                    new PageImpl<IssuersCredential>(List.of(issuersCredential))
            );

            HoldersCredential holdersCredential = mock(HoldersCredential.class);

            when(holdersCredentialRepository.getByHolderDidAndIssuerDidAndTypeAndStored(
                    any(String.class),
                    any(String.class),
                    eq(MIWVerifiableCredentialType.SUMMARY_CREDENTIAL),
                    eq(false)
            )).thenReturn(List.of(holdersCredential, holdersCredential, holdersCredential));

            assertDoesNotThrow(() -> issuersCredentialService.issueBpnCredential(baseWallet, holderWallet, false));
        }


        private void shouldIssueBpnCredential(Wallet baseWallet, Wallet holderWallet) {
            x21559Generator gen = new x21559Generator();
            KeyPair baseWalletKeys;
            try {
                baseWalletKeys = gen.generateKey();
            } catch (KeyGenerationException e) {
                throw new AssertionError(e);
            }

            when(miwSettings.contractTemplatesUrl()).thenReturn("https://templates.com");
            when(walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(baseWallet.getId()))
                    .thenReturn(baseWalletKeys.getPrivateKey().asByte());
            when(miwSettings.vcExpiryDate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(2))));
            when(holdersCredentialRepository.save(any(HoldersCredential.class)))
                    .thenAnswer(new Answer<HoldersCredential>() {
                                    @Override
                                    public HoldersCredential answer(InvocationOnMock invocation) throws Throwable {
                                        HoldersCredential argument = invocation.getArgument(0, HoldersCredential.class);
                                        argument.setId(42L);
                                        return argument;
                                    }
                                }
                    );
        }

    }


    @Nested
    class getCredentials {

        @Test
        void shouldReturnCredentials() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            String holderIdentifier = TestUtils.getRandomBpmNumber();

            mockPages(callerBpn, holderIdentifier);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> issuersCredentialService.getCredentials(
                    "credentialId",
                    holderIdentifier,
                    List.of("type1", "type2"),
                    "sortColumn",
                    "asc",
                    1,
                    10,
                    callerBpn
            ));
            assertNotNull(verifiableCredentials);
            assertFalse(verifiableCredentials.isEmpty());
        }

        @Test
        void shouldReturnCredentialsWithoutHolderIdentifier() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            String holderIdentifier = "";

            mockPages(callerBpn, holderIdentifier);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> issuersCredentialService.getCredentials(
                    "credentialId",
                    holderIdentifier,
                    List.of("type1", "type2"),
                    "sortColumn",
                    "asc",
                    1,
                    10,
                    callerBpn
            ));
            assertNotNull(verifiableCredentials);
            assertFalse(verifiableCredentials.isEmpty());
        }

        @Test
        void shouldReturnCredentialsWithoutCredentialId() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            String holderIdentifier = TestUtils.getRandomBpmNumber();

            mockPages(callerBpn, holderIdentifier);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> issuersCredentialService.getCredentials(
                    "",
                    holderIdentifier,
                    List.of("type1", "type2"),
                    "sortColumn",
                    "asc",
                    1,
                    10,
                    callerBpn
            ));
            assertNotNull(verifiableCredentials);
            assertFalse(verifiableCredentials.isEmpty());
        }

        @Test
        void shouldReturnCredentialsWithoutTypes() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            String holderIdentifier = TestUtils.getRandomBpmNumber();

            mockPages(callerBpn, holderIdentifier);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> issuersCredentialService.getCredentials(
                    "",
                    holderIdentifier,
                    Collections.emptyList(),
                    "sortColumn",
                    "asc",
                    1,
                    10,
                    callerBpn
            ));
            assertNotNull(verifiableCredentials);
            assertFalse(verifiableCredentials.isEmpty());
        }


    }

    private void mockPages(String callerBpn, String holderIdentifier) {
        Wallet callerWallet = mockWallet(callerBpn, "did:web:random#caller");
        Wallet holderWallet = mockWallet(holderIdentifier, "did:web:random#holder");

        when(commonService.getWalletByIdentifier(callerBpn)).thenReturn(callerWallet);
        when(commonService.getWalletByIdentifier(holderIdentifier)).thenReturn(holderWallet);
        VerifiableCredential verifiableCredential = mockCredential(
                List.of("TypeA,TypeB"),
                List.of(mockCredentialSubject())
        );
        IssuersCredential issuersCredential = mockIssuerCredential(verifiableCredential);

        // filter(Specification<E> specification, FilterRequest filter) is called
        when(issuersCredentialRepository.findAll(
                any(Specification.class),
                any(PageRequest.class)
        )).thenReturn(new PageImpl<IssuersCredential>(
                List.of(issuersCredential)));
    }

    private static IssuersCredential mockIssuerCredential(VerifiableCredential verifiableCredential) {


        IssuersCredential cred = mock(IssuersCredential.class);
        when(cred.getCredentialId()).thenReturn("credentialId");
        when(cred.getData()).thenReturn(verifiableCredential);
        return cred;
    }

    private static Wallet mockWallet(String bpn, String did) {
        Wallet wallet = mock(Wallet.class);
        when(wallet.getId()).thenReturn(new Random().nextLong());
        when(wallet.getName()).thenReturn("WalletName");
        when(wallet.getBpn()).thenReturn(bpn);
        when(wallet.getDid()).thenReturn(did);
        when(wallet.getDidDocument()).thenReturn(null);
        when(wallet.getAlgorithm()).thenReturn("Ed25519");
        when(wallet.getCreatedAt()).thenReturn(new Date());
        when(wallet.getModifiedAt()).thenReturn(new Date());
        when(wallet.getModifiedFrom()).thenReturn(null);
        return wallet;
    }

    private static DidDocument mockDidDocument() {

        HashMap<String, Object> m = new HashMap<>();
        m.put("id", "did:web:example.com");
        m.put("@context", List.of("https://www.w3.org/ns/did/v1"));
        m.put("verificationMethod", Collections.emptyList());

        return new DidDocument(m);
    }

    private static List<VerificationMethod> mockVerificationMethod() {
        HashMap<String, Object> m = new HashMap<>();
        m.put("id", "did:web:example.com#keys1");
        m.put("type", "type");
        m.put("controller", "controller");


        return List.of(new VerificationMethod(m));
    }


    private static VerifiableCredential mockCredential(
            List<String> types,
            List<VerifiableCredentialSubject> credentialSubjects
    ) {

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
                        .credentialSubject(credentialSubjects)
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


    private Map<String, Wallet> mockBaseAndHolderWallet(){
        String baseWalletBpn = TestUtils.getRandomBpmNumber();
        List<VerificationMethod> verificationMethod = mockVerificationMethod();
        DidDocument baseWalletDidDocument = mockDidDocument();
        baseWalletDidDocument.put("verificationMethod", verificationMethod);
        Wallet baseWallet = mockWallet(baseWalletBpn, "did:web:basewallet");
        when(baseWallet.getDidDocument()).thenReturn(baseWalletDidDocument);
        String holderWalletBpn = TestUtils.getRandomBpmNumber();
        Wallet holderWallet = mockWallet(holderWalletBpn, "did:web:holderwallet");

        return Map.of("base", baseWallet,"holder",holderWallet);
    }
}
