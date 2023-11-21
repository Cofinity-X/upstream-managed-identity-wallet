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
import org.eclipse.tractusx.ssi.lib.model.did.DidDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DidDocumentServiceTest {

    private static CommonService commonService;

    private static DidDocumentService didDocumentService;

    @BeforeAll
    public static void beforeAll() {
        commonService = mock(CommonService.class);
        didDocumentService = new DidDocumentService(commonService);
    }

    @BeforeEach
    public void beforeEach() {
        Mockito.reset(commonService);
    }

    @Test
    void shouldCreateDidDocument() {
        Wallet mockWallet = MockUtil.mockWallet("bpn", MockUtil.generateDid("localhost"), MockUtil.generateKeys());
        when(commonService.getWalletByIdentifier("bpn")).thenReturn(mockWallet);

        DidDocument didDocument = assertDoesNotThrow(() -> didDocumentService.getDidDocument("bpn"));
        assertEquals(MockUtil.generateDid("localhost").toUri(), didDocument.getId());
    }
}