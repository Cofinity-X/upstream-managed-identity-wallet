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

import com.smartsensesolutions.java.commons.specification.SpecificationUtil;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.eclipse.tractusx.managedidentitywallets.MockUtil;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletKeyRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.dto.CreateWalletRequest;
import org.eclipse.tractusx.managedidentitywallets.exception.BadDataException;
import org.eclipse.tractusx.managedidentitywallets.exception.DuplicateWalletProblem;
import org.eclipse.tractusx.managedidentitywallets.exception.ForbiddenException;
import org.eclipse.tractusx.managedidentitywallets.utils.EncryptionUtils;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private static IssuersCredentialService issuersCredentialService;

    private static CommonService commonService;

    private static WalletService walletService;


    @BeforeAll
    public static void beforeAll() throws SQLException {
        walletRepository = Mockito.mock(WalletRepository.class);
        miwSettings = Mockito.mock(MIWSettings.class);
        encryptionUtils = Mockito.mock(EncryptionUtils.class);
        walletKeyService = Mockito.mock(WalletKeyService.class);
        holdersCredentialRepository = Mockito.mock(HoldersCredentialRepository.class);
        SpecificationUtil<Wallet> walletSpecificationUtil = new SpecificationUtil<Wallet>();
        issuersCredentialService = Mockito.mock(IssuersCredentialService.class);
        commonService = Mockito.mock(CommonService.class);

        Connection connection = mock(Connection.class);

        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);


        walletService = new WalletService(
                walletRepository,
                miwSettings,
                encryptionUtils,
                walletKeyService,
                holdersCredentialRepository,
                walletSpecificationUtil,
                issuersCredentialService,
                commonService,
                new DataSourceTransactionManager(dataSource)
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
    class createAuthorityWallet {

        // test !walletRepository.existsByBpn(miwSettings.authorityWalletBpn())

        @Test
            // logs only stuff, wtf
        void shouldNotCreateAuthorityWallet() {
            String miwSettingsBpn = TestUtils.getRandomBpmNumber();
            when(miwSettings.authorityWalletBpn()).thenReturn(miwSettingsBpn);
            when(miwSettings.authorityWalletName()).thenReturn("AuthorityWallet");
            when(walletRepository.existsByBpn(any(String.class))).thenReturn(true);
            assertDoesNotThrow(() -> walletService.createAuthorityWallet());
        }

        @Test
            // logs only stuff, wtf
        void shouldCreateAuthorityWallet() {
            String miwSettingsBpn = TestUtils.getRandomBpmNumber();
            when(miwSettings.authorityWalletBpn()).thenReturn(miwSettingsBpn);
            when(miwSettings.authorityWalletName()).thenReturn("AuthorityWallet");
            when(walletRepository.existsByBpn(any(String.class))).thenReturn(false);
            when(miwSettings.host()).thenReturn("localhost");

            String did = "did:web:random";
            Wallet createdWallet = MockUtil.mockWallet(
                    miwSettingsBpn,
                    MockUtil.generateDid("random"),
                    MockUtil.generateKeys()
            );
            when(createdWallet.getName()).thenReturn("TestWallet");
            when(createdWallet.getId()).thenReturn(42L);
            when(walletRepository.save(any(Wallet.class))).thenReturn(createdWallet);

            WalletKeyRepository walletKeyRepository = mock(WalletKeyRepository.class);
            when(walletKeyService.getRepository()).thenReturn(walletKeyRepository);

            assertDoesNotThrow(() -> walletService.createAuthorityWallet());
        }

        private void createWallet(String callerBpn, String miwSettingsBpn) {
            CreateWalletRequest cwr = mock(CreateWalletRequest.class);
            when(cwr.getName()).thenReturn("TestWallet");

            String bpn = TestUtils.getRandomBpmNumber();
            when(cwr.getBpn()).thenReturn(bpn);
            when(miwSettings.authorityWalletBpn()).thenReturn(miwSettingsBpn);
            when(miwSettings.host()).thenReturn("localhost");


            Wallet createdWallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("random"), MockUtil.generateKeys());
            when(createdWallet.getName()).thenReturn("TestWallet");
            when(createdWallet.getId()).thenReturn(42L);
            when(walletRepository.save(any(Wallet.class))).thenReturn(createdWallet);

            WalletKeyRepository walletKeyRepository = mock(WalletKeyRepository.class);
            when(walletKeyService.getRepository()).thenReturn(walletKeyRepository);

            Wallet issuerWallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("random2"), MockUtil.generateKeys());
            when(walletRepository.getByBpn(bpn)).thenReturn(issuerWallet);
            Wallet wallet = walletService.createWallet(cwr, callerBpn);
        }
    }

    @Nested
    class getWalletsTest {

        @Test
        void shouldNotThrow() {
            assertDoesNotThrow(() -> walletService.getWallets(0, 0, "foo", "asc"));
        }
    }

    @Nested
    class createWalletTest {

        @Test
        void shouldCreateWallet() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            assertDoesNotThrow(() -> createWallet(callerBpn, callerBpn));
        }

        @Test
        void shouldThrowForbiddenExceptionWhenCallerAndAuthorityDontMatch() {
            String callerBpn = TestUtils.getRandomBpmNumber();
            assertThrows(ForbiddenException.class, () -> createWallet("12345", callerBpn));
        }

        @Test
        void shouldThrowDuplicateWhenWalletWithBpnAlreadyExists() {
            when(walletRepository.existsByBpn(any(String.class))).thenReturn(true);

            String callerBpn = TestUtils.getRandomBpmNumber();
            assertThrows(DuplicateWalletProblem.class, () -> createWallet(callerBpn, callerBpn));
        }

        private void createWallet(String callerBpn, String miwSettingsBpn) {
            CreateWalletRequest cwr = mock(CreateWalletRequest.class);
            when(cwr.getName()).thenReturn("TestWallet");

            String bpn = TestUtils.getRandomBpmNumber();
            when(cwr.getBpn()).thenReturn(bpn);
            when(miwSettings.authorityWalletBpn()).thenReturn(miwSettingsBpn);
            when(miwSettings.host()).thenReturn("localhost");


            Wallet createdWallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("random"), MockUtil.generateKeys());
            when(createdWallet.getName()).thenReturn("TestWallet");
            when(createdWallet.getId()).thenReturn(42L);
            when(walletRepository.save(any(Wallet.class))).thenReturn(createdWallet);

            WalletKeyRepository walletKeyRepository = mock(WalletKeyRepository.class);
            when(walletKeyService.getRepository()).thenReturn(walletKeyRepository);

            Wallet issuerWallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("random2"), MockUtil.generateKeys());
            when(walletRepository.getByBpn(bpn)).thenReturn(issuerWallet);
            Wallet wallet = walletService.createWallet(cwr, callerBpn);
        }
    }

    @Nested
    class getWalletByIdentifierTest {

        @Test
        void shouldReturnWalletWithCredentials() {
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            VerifiableCredential verifiableCredential = MockUtil.mockCredential(
                    List.of("VerifiableCredential"),
                    List.of(MockUtil.mockCredentialSubject()),
                    keyPair,
                    "localhost",
                    Instant.now().plus(Duration.ofDays(5))
            );


            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);

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
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            VerifiableCredential verifiableCredential = MockUtil.mockCredential(
                    List.of("VerifiableCredential"),
                    List.of(MockUtil.mockCredentialSubject()),
                    keyPair,
                    "localhost",
                    Instant.now().plus(Duration.ofDays(5))
            );


            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);

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
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);
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
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);
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
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            Map<String, String> message = assertDoesNotThrow(() -> walletService.storeCredential(
                    MockUtil.mockCredential(
                            List.of("VerifiableCredential"),
                            List.of(MockUtil.mockCredentialSubject()),
                            keyPair,
                            "localhost",
                            Instant.now().plus(Duration.ofDays(5))
                    ),
                    "identifier",
                    bpn
            ));
            assertNotNull(message);
        }

        @Test
        void shouldNotStoreCredentialWhenNoBPNMatched() {
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            assertThrows(ForbiddenException.class, () -> walletService.storeCredential(
                    MockUtil.mockCredential(
                            List.of("VerifiableCredential"),
                            List.of(MockUtil.mockCredentialSubject()),
                            keyPair,
                            "localhost",
                            Instant.now().plus(Duration.ofDays(5))
                    ),
                    "identifier",
                    bpn+"asd"
            ));
        }

        @Test
        void shouldNotStoreCredentialWhenNoTypesContained() {
            KeyPair keyPair = MockUtil.generateKeys();
            String bpn = "bpn";
            Wallet wallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(wallet);

            assertThrows(BadDataException.class, () -> walletService.storeCredential(
                    MockUtil.mockCredential(
                            Collections.emptyList(),
                            List.of(MockUtil.mockCredentialSubject()),
                            keyPair,
                            "localhost",
                            Instant.now().plus(Duration.ofDays(5))
                    ),
                    "identifier",
                    bpn
            ));
        }
    }


}
