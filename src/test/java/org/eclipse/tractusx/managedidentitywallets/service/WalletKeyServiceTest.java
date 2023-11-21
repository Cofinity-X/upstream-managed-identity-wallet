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
import java.io.IOException;
import java.io.StringWriter;
import lombok.SneakyThrows;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.eclipse.tractusx.managedidentitywallets.MockUtil;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.Wallet;
import org.eclipse.tractusx.managedidentitywallets.dao.entity.WalletKey;
import org.eclipse.tractusx.managedidentitywallets.dao.repository.WalletKeyRepository;
import org.eclipse.tractusx.managedidentitywallets.utils.EncryptionUtils;
import org.eclipse.tractusx.managedidentitywallets.utils.TestUtils;
import org.eclipse.tractusx.ssi.lib.crypt.KeyPair;
import org.eclipse.tractusx.ssi.lib.crypt.x21559.x21559PrivateKey;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class WalletKeyServiceTest {
    private static WalletKeyRepository walletKeyRepository;

    private static EncryptionUtils encryptionUtils;

    private static WalletKeyService walletKeyService;

    @BeforeAll
    public static void beforeAll(){
        walletKeyRepository = mock(WalletKeyRepository.class);
        encryptionUtils = mock(EncryptionUtils.class);
        walletKeyService = new WalletKeyService(walletKeyRepository, new SpecificationUtil<WalletKey>(), encryptionUtils);
    }

    @BeforeEach
    public void beforeEach(){
        Mockito.reset(walletKeyRepository, encryptionUtils);
    }

    @Test
    void shouldReturnPrivateKeyObject() throws IOException {
        String bpn = TestUtils.getRandomBpmNumber();
        Did did = MockUtil.generateDid("localhost");
        KeyPair keys = MockUtil.generateKeys();
        Wallet mockWallet = MockUtil.mockWallet(bpn, did, keys);

        WalletKey key = mock(WalletKey.class);
        when(key.getPrivateKey()).thenReturn(getPrivateKeyString(keys.getPrivateKey().asByte()));
        when(key.getPublicKey()).thenReturn(getPublicKeyString(keys.getPublicKey().asByte()));

        when(walletKeyRepository.getByWalletId(any(Long.class))).thenReturn(key);
        when(encryptionUtils.decrypt(any())).thenReturn(getPrivateKeyString(keys.getPrivateKey().asByte()));

        x21559PrivateKey x21559PrivateKey = assertDoesNotThrow(() -> walletKeyService.getPrivateKeyByWalletIdentifier(42));
        assertNotNull(x21559PrivateKey);
    }

    @Test
    void shouldReturnPrivateKeyByteArray() throws IOException {
        String bpn = TestUtils.getRandomBpmNumber();
        Did did = MockUtil.generateDid("localhost");
        KeyPair keys = MockUtil.generateKeys();
        Wallet mockWallet = MockUtil.mockWallet(bpn, did, keys);

        WalletKey key = mock(WalletKey.class);
        when(key.getPrivateKey()).thenReturn(getPrivateKeyString(keys.getPrivateKey().asByte()));
        when(key.getPublicKey()).thenReturn(getPublicKeyString(keys.getPublicKey().asByte()));

        when(walletKeyRepository.getByWalletId(any(Long.class))).thenReturn(key);
        when(encryptionUtils.decrypt(any())).thenReturn(getPrivateKeyString(keys.getPrivateKey().asByte()));

        byte[] bytes = assertDoesNotThrow(() -> walletKeyService.getPrivateKeyByWalletIdentifierAsBytes(42));
        assertTrue(bytes.length > 0);
    }

    @Test
    void testInstance(){
        assertNotNull(walletKeyService.getRepository());
        assertNotNull(walletKeyService.getSpecificationUtil());
    }

    private String getPrivateKeyString(byte[] privateKeyBytes) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKeyBytes));
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }


    private String getPublicKeyString(byte[] publicKeyBytes) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKeyBytes));
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }
}