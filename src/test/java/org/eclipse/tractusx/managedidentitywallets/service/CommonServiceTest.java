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

import org.eclipse.tractusx.managedidentitywallets.MockUtil;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletKeyRepository;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletRepository;
import org.eclipse.tractusx.managedidentitywallets.exception.WalletNotFoundProblem;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.exception.DidParseException;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CommonServiceTest {
    private static WalletRepository walletRepository;
    private static CommonService commonService;
    @BeforeAll
    public static void beforeAll(){
        walletRepository = mock(WalletRepository.class);
        commonService = new CommonService(walletRepository);
    }

    @BeforeEach
    public void beforeEach(){
        Mockito.reset(walletRepository);
    }

    @Test
    void shouldReturnWalletIfBPN(){
        String bpn = TestUtils.getRandomBpmNumber();
        Wallet mockWallet = MockUtil.mockWallet(bpn, MockUtil.generateDid("localhost"), MockUtil.generateKeys());
        when(walletRepository.getByBpn(bpn)).thenReturn(mockWallet);

        Wallet wallet = assertDoesNotThrow(() -> commonService.getWalletByIdentifier(bpn));
        assertNotNull(wallet);
    }

    @Test
    void shouldReturnWalletIfDid(){
        String bpn = TestUtils.getRandomBpmNumber();
        Did did = MockUtil.generateDid("localhost");
        Wallet mockWallet = MockUtil.mockWallet(bpn, did, MockUtil.generateKeys());
        when(walletRepository.getByDid(did.toUri().toString())).thenReturn(mockWallet);

        Wallet wallet = assertDoesNotThrow(() -> commonService.getWalletByIdentifier(did.toUri().toString()));
        assertNotNull(wallet);
    }

    @Test
    void shouldThrowWalletNotFoundIfDidAndDidParseExceptionOccurs(){
        String bpn = TestUtils.getRandomBpmNumber();
        Did did = MockUtil.generateDid("localhost");
        Wallet mockWallet = MockUtil.mockWallet(bpn, did, MockUtil.generateKeys());
        when(mockWallet.getDid()).thenReturn("12345");
        when(walletRepository.getByDid(did.toUri().toString())).thenThrow(DidParseException.class);

       assertThrows(WalletNotFoundProblem.class, () -> commonService.getWalletByIdentifier(did.toUri().toString()));
    }
}