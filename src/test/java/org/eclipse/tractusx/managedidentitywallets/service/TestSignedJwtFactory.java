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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.eclipse.tractusx.ssi.lib.crypt.IPrivateKey;
import org.eclipse.tractusx.ssi.lib.crypt.octet.OctetKeyPairFactory;
import org.eclipse.tractusx.ssi.lib.jwt.SignedJwtFactory;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.serialization.jwt.SerializedVerifiablePresentation;

public class TestSignedJwtFactory extends SignedJwtFactory {

    @FunctionalInterface
    public interface RandomException {

        void random();

    }

    private final OctetKeyPairFactory octetKeyPairFactory;

    public TestSignedJwtFactory(OctetKeyPairFactory octetKeyPairFactory) {
        super(octetKeyPairFactory);
        this.octetKeyPairFactory = octetKeyPairFactory;
    }

    @Override
    public SignedJWT create(
            Did didIssuer,
            String audience,
            SerializedVerifiablePresentation serializedPresentation,
            IPrivateKey privateKey
    ) {
        try {
            String issuer = didIssuer.toString();
            String subject = didIssuer.toString();
            Map<String, Object> vp = (Map) (new ObjectMapper()).readValue(
                    serializedPresentation.getJson(),
                    HashMap.class
            );
            JWTClaimsSet claimsSet = (new JWTClaimsSet.Builder()).issuer(issuer)
                                                                 .subject(subject)
                                                                 .audience(audience)
                                                                 .claim("vp", vp)
                                                                 .expirationTime(Date.from(
                                                                         Instant.now().minus(Duration.ofDays(42))))
                                                                 .jwtID(
                                                                         UUID.randomUUID().toString())
                                                                 .build();
            OctetKeyPair octetKeyPair = this.octetKeyPairFactory.fromPrivateKey(privateKey);
            return createSignedES256Jwt2(octetKeyPair, claimsSet, issuer);
        } catch (JsonMappingException e) {
            throw new RuntimeException(e);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignedJWT createSignedES256Jwt2(
            OctetKeyPair privateKey, JWTClaimsSet claimsSet, String issuer) {
        JWSSigner signer;
        try {

            signer = new Ed25519Signer(privateKey);
            if (!signer.supportedJWSAlgorithms().contains(JWSAlgorithm.EdDSA)) {
                throw new RuntimeException(
                        String.format(
                                "Invalid signing method. Supported signing methods: %s",
                                signer.supportedJWSAlgorithms().stream()
                                      .map(JWSAlgorithm::getName)
                                      .collect(Collectors.joining(", "))));
            }

            var algorithm = JWSAlgorithm.EdDSA;
            var type = JOSEObjectType.JWT;
            var header =
                    // FIXME issuer must be actual keyId and not only DID
                    new JWSHeader(
                            algorithm,
                            type,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            issuer,
                            true,
                            null,
                            null);
            var vc = new SignedJWT(header, claimsSet);

            vc.sign(signer);
            return vc;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
