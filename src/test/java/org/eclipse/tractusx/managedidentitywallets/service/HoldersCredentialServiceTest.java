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
import javax.sql.DataSource;
import org.eclipse.tractusx.managedidentitywallets.MockUtil;
import org.eclipse.tractusx.managedidentitywallets.config.MIWSettings;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.HoldersCredential;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.HoldersCredentialRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.ForbiddenException;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.exception.KeyGenerationException;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethod;
import org.eclipse.tractusx.ssi.lib.model.did.DidMethodIdentifier;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredentialBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.data.domain.PageImpl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HoldersCredentialServiceTest {

    private static MIWSettings miwSettings;

    private static WalletKeyService walletKeyService;

    private static HoldersCredentialRepository holdersCredentialRepository;

    private static CommonService commonService;

    private static HoldersCredentialService holdersCredentialService;

    @BeforeAll
    public static void beforeAll() throws SQLException {
        miwSettings = Mockito.mock(MIWSettings.class);
        walletKeyService = Mockito.mock(WalletKeyService.class);
        holdersCredentialRepository = Mockito.mock(HoldersCredentialRepository.class);
        commonService = Mockito.mock(CommonService.class);

        Connection connection = mock(Connection.class);

        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);


        holdersCredentialService = new HoldersCredentialService(
                holdersCredentialRepository,
                commonService,
                new SpecificationUtil<HoldersCredential>(),
                walletKeyService
        );
    }

    @BeforeEach
    public void beforeEach() {
        Mockito.reset(
                miwSettings,
                walletKeyService,
                holdersCredentialRepository,
                commonService
        );
    }

    @Nested
    class issueCredentialTest {

        @Test
        void shouldIssueCredential() throws KeyGenerationException {
            String issuerBpn = TestUtils.getRandomBpmNumber();
            VerifiableCredential vc = shouldIssueCredential(issuerBpn);
            VerifiableCredential verifiableCredential = assertDoesNotThrow(() -> holdersCredentialService.issueCredential(
                    vc,
                    issuerBpn
            ));
        }

        @Test
        void shouldNotIssueCredentialWhenCallerDoesNotMatchIssuer() throws KeyGenerationException {
            String issuerBpn = TestUtils.getRandomBpmNumber();
            String callerBpn = TestUtils.getRandomBpmNumber();
            VerifiableCredential vc = shouldIssueCredential(issuerBpn);
            assertThrows(ForbiddenException.class, () -> holdersCredentialService.issueCredential(
                    vc,
                    callerBpn
            ));
        }

        VerifiableCredential shouldIssueCredential(String issuerBpn) throws KeyGenerationException {
            KeyPair issuerKeys = MockUtil.generateKeys();
            Did issuer = new Did(new DidMethod("web"), new DidMethodIdentifier("localhost"), null);
            Wallet issuerWallet = MockUtil.mockWallet(issuerBpn, issuer, issuerKeys);
            final VerifiableCredentialBuilder builder = MockUtil.getCredentialBuilder(
                    List.of("VerifiableCredential", "SummaryCredential"),
                    List.of(MockUtil.mockCredentialSubject()),
                    Instant.now().plus(Duration.ofDays(5)),
                    issuer
            );
            VerifiableCredential vc = builder.build();


            when(walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(issuerWallet.getId()))
                    .thenReturn(issuerKeys.getPrivateKey().asByte());
            when(commonService.getWalletByIdentifier(vc.getIssuer().toString())).thenReturn(issuerWallet);
            MockUtil.makeCreateWorkForHolder(holdersCredentialRepository);
            return vc;
        }


    }

    @Nested
    class getCredentialsTest {

        @ParameterizedTest
        @ValueSource(strings = {"", "123456"})
        void shouldReturnCredentialsVariableCredentialId(String credentialId) throws KeyGenerationException {
            String caller = TestUtils.getRandomBpmNumber();

            KeyPair keyPair = MockUtil.generateKeys();
            Did holder = new Did(new DidMethod("web"), new DidMethodIdentifier("localhost"), null);
            Wallet holderWallet = MockUtil.mockWallet(caller, holder, keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(holderWallet);
            MockUtil.makeFilterWorkForHolder(holdersCredentialRepository);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> holdersCredentialService.getCredentials(
                    credentialId,
                    "did:web:issuer",
                    List.of("VerifiableCredential", "SummaryCredential"),
                    "col",
                    "asc",
                    42, 42,
                    caller
            ));
            assertTrue(verifiableCredentials.hasContent());
            assertEquals(1, verifiableCredentials.getTotalElements());
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "did:web:issuer"})
        void shouldReturnCredentialsVariableIssuerIdentifier(String issuerId) throws KeyGenerationException {
            String caller = TestUtils.getRandomBpmNumber();

            KeyPair keyPair = MockUtil.generateKeys();
            Did holder = new Did(new DidMethod("web"), new DidMethodIdentifier("localhost"), null);
            Wallet holderWallet = MockUtil.mockWallet(caller, holder, keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(holderWallet);
            MockUtil.makeFilterWorkForHolder(holdersCredentialRepository);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> holdersCredentialService.getCredentials(
                    "123456",
                    issuerId,
                    List.of("VerifiableCredential", "SummaryCredential"),
                    "col",
                    "asc",
                    42, 42,
                    caller
            ));
            assertTrue(verifiableCredentials.hasContent());
            assertEquals(1, verifiableCredentials.getTotalElements());
        }

        @Test
        void shouldReturnCredentialsWithEmptyTypes() throws KeyGenerationException {
            String caller = TestUtils.getRandomBpmNumber();

            KeyPair keyPair = MockUtil.generateKeys();
            Did holder = new Did(new DidMethod("web"), new DidMethodIdentifier("localhost"), null);
            Wallet holderWallet = MockUtil.mockWallet(caller, holder, keyPair);
            when(commonService.getWalletByIdentifier(any(String.class))).thenReturn(holderWallet);
            MockUtil.makeFilterWorkForHolder(holdersCredentialRepository);

            PageImpl<VerifiableCredential> verifiableCredentials = assertDoesNotThrow(() -> holdersCredentialService.getCredentials(
                    "123456",
                    "did:web:issuer",
                    Collections.emptyList(),
                    "col",
                    "asc",
                    42, 42,
                    caller
            ));
            assertTrue(verifiableCredentials.hasContent());
            assertEquals(1, verifiableCredentials.getTotalElements());
        }
    }


}