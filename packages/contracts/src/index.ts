// SPDX-License-Identifier: Apache-2.0
import {Type} from '@sinclair/typebox';
export const Id=Type.String({format:'uuid'});
export const SourceInput=Type.Object({name:Type.String({minLength:1,maxLength:120}),host:Type.Literal('source-postgres'),port:Type.Literal(5432),database:Type.Literal('harbor'),schema:Type.Literal('public'),secretRef:Type.Literal('demo-postgres')},{additionalProperties:false});
export const AssetEdit=Type.Object({description:Type.Optional(Type.String({maxLength:10000})),ownerId:Type.Optional(Type.Union([Id,Type.Null()]))},{additionalProperties:false,minProperties:1});
export const ScanRecord=Type.Object({externalId:Type.String({maxLength:256}),name:Type.String({maxLength:512}),qualifiedName:Type.String({maxLength:1024}),type:Type.String({maxLength:64}),parentExternalId:Type.Optional(Type.Union([Type.String({maxLength:256}),Type.Null()])),metadata:Type.Record(Type.String(),Type.Unknown())},{additionalProperties:false});
export const ScanCompletion=Type.Object({observedAt:Type.String({format:'date-time'}),sourceVersion:Type.String({maxLength:256}),permissionFingerprint:Type.String({maxLength:256}),complete:Type.Literal(true),records:Type.Array(ScanRecord,{maxItems:10000})},{additionalProperties:false});
