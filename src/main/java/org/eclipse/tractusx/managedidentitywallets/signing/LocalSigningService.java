/*
 * *******************************************************************************
 *  Copyright (c) 2021,2024 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.managedidentitywallets.signing;

import com.nimbusds.jwt.JWT;
import org.eclipse.tractusx.managedidentitywallets.domain.BusinessPartnerNumber;
import org.eclipse.tractusx.managedidentitywallets.domain.DID;

import java.util.Set;

/**
 * Specialized interface for SigningServices that will sign credentials/presentations locally
 * (may retrieve the keys from remote via KeyProvider)
 *
 * @see SigningService
 * @see KeyProvider
 */
public interface LocalSigningService extends SigningService {
    /**
     * @param keyProvider the KeyProvider to be used by the implementation
     */
    void setKeyProvider(KeyProvider keyProvider);
}
