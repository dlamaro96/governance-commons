// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance, FastifyRequest, HTTPMethods } from 'fastify';
import { Type, type TSchema } from '@sinclair/typebox';
import { scope, type Tx } from '../../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../../packages/authz/src/index.ts';
import { parseDomainTypeFile } from '../../../packages/domain/src/business-domain-type.ts';
import { parseDomainTypeMigrationFile } from '../../../packages/domain/src/business-domain-migration.ts';
import { domainRead, domainPreview, domainMutate } from '../../../packages/domain/src/business-domain-service.ts';
import { authorizeDomain, domainQuery, domainFailure } from '../../../packages/domain/src/business-domain-store.ts';
import type { DomainCreateRequest, DomainEditRequest, DomainStateRequest, DomainPlacementRequest,
  DomainFileValidationRequest, DomainTypeDefinitionRequest, DomainTypePublicationRequest,
  DomainTypeMigrationPreviewRequest, DomainTypeMigrationRequest, DomainHierarchyPreviewRequest,
  DomainHierarchyRequest } from '../../../packages/domain/src/business-domain-contracts.ts';
import type { DomainPageQuery, DomainHistoryQuery, DomainInventoryQuery } from '../../../packages/domain/src/business-domain-service-contracts.ts';
import { authenticate } from './security.ts';
import { record, once } from './repository.ts';
import { domainHttp, installDomainHttpValidation, domainProblemSchema, domainParams, domainQuerySchema,
  domainSchemaCheck, domainJSONInvalid, domainRawQuery, domainExpectedVersion, domainIdempotencyKey,
  checkDomainData } from './business-domain-http.ts';

type Route = {
  readonly params?: readonly string[]; readonly query?: readonly string[]; readonly body?: TSchema;
  readonly response: TSchema; readonly created?: boolean; readonly mutation?: boolean;
  readonly expected?: 'positive' | 'placement'; readonly consent?: boolean; readonly hierarchy?: boolean;
};
type ParsedRequest = { principal: Principal; page: Record<string, string | number>; expected?: number; key?: string };
const hooks = { record, once };
const typeId = (req: FastifyRequest) => (req.params as { typeId: string }).typeId;
const id = (req: FastifyRequest) => (req.params as { id: string }).id;
const body = <T>(req: FastifyRequest) => req.body as T;
const pageFields = ['limit', 'cursor', 'q'] as const;
const historyFields = ['limit', 'cursor'] as const;
const previewRequired = () => new Problem(428, 'DOMAIN_PREVIEW_REQUIRED', 'Review a ready preview before execution.');

/** Encapsulation keeps these strict parsers and schemas local to the new APIs.
 * Every mutation delegates idempotency, replay authorization and deferred
 * constraint completion to the same domain service used by non-HTTP callers. */
export async function installBusinessDomains(app: FastifyInstance): Promise<void> {
  await app.register(async child => {
    const parsed = new WeakMap<FastifyRequest, ParsedRequest>();
    installDomainHttpValidation(child);
    child.addHook('onRequest', async req => {
      const { principal } = await authenticate(req);
      parsed.set(req, { principal, page: {} });
    });
    child.setErrorHandler((original, req, reply) => {
      const source = original as Error & { validation?: unknown; statusCode?: number };
      const error = original instanceof Problem ? original : source.statusCode === 429
        ? new Problem(429, 'RATE_LIMITED', 'Too many requests. Retry after the indicated interval.')
        : source.validation || [400, 413, 415].includes(source.statusCode ?? 0) ? domainJSONInvalid() : domainFailure(original);
      const known = error instanceof Problem ? error : new Problem(500, 'DOMAIN_STORAGE_INVALID', 'The domain operation could not be completed. Use the correlation ID for support.');
      if (known.status === 503 && known.code === 'DOMAIN_RETRY') reply.header('Retry-After', '5');
      if (known.status >= 500) req.log.error({ code: known.code, correlationId: req.id }, 'Domain request failed; details redacted');
      reply.code(known.status).type('application/problem+json').send({ type: 'about:blank', title: known.status >= 500 ? 'Service unavailable' : 'Request rejected',
        status: known.status, code: known.code, detail: known.status === 500 ? 'The domain operation could not be completed. Use the correlation ID for support.' : known.message,
        correlationId: req.id, ...(known.issues && known.status === 422 ? { issues: known.issues } : {}) });
    });
    const current = (req: FastifyRequest): ParsedRequest => {
      const value = parsed.get(req); if (!value) throw new Problem(401, 'SESSION_REQUIRED', 'Sign in to continue.'); return value;
    };
    const expected = (req: FastifyRequest) => current(req).expected!;
    const page = <T>(req: FastifyRequest) => current(req).page as T;
    const mutate = (req: FastifyRequest, tx: Tx, p: Principal, request: Parameters<typeof domainMutate>[3]) =>
      domainMutate(tx, p, current(req).key!, request, req.id, hooks);

    function route(method: HTTPMethods, url: string, spec: Route, work: (req: FastifyRequest, tx: Tx, p: Principal) => Promise<unknown>) {
      const status = spec.created ? 201 : 200;
      const paramsSchema = domainParams(spec.params ?? []);
      child.route({ method, url: '/api/v1' + url, bodyLimit: 1048576,
        schema: { params: paramsSchema, querystring: domainQuerySchema(spec.query ?? []),
          headers: Type.Object({ ...(spec.mutation ? { 'idempotency-key': Type.String({ minLength: 8, maxLength: 128 }) } : {}),
            ...(spec.expected ? { 'if-match': Type.String({ maxLength: 12 }) } : {}) }, { additionalProperties: true }),
          ...(spec.body ? { body: spec.body } : {}), response: { [status]: spec.response, '4xx': domainProblemSchema, '5xx': domainProblemSchema } },
        preValidation: async req => {
          const state = current(req);
          // Raw spelling remains authoritative even if Fastify's query parser
          // flattens duplicates or AJV would coerce/remove submitted fields.
          state.page = domainRawQuery(req, spec.query ?? []);
          if (!domainSchemaCheck(paramsSchema, { ...(req.params as Record<string, unknown>) })) throw domainJSONInvalid();
          const routeVersion = (req.params as { version?: string }).version;
          if (routeVersion !== undefined && Number(routeVersion) > 2147483647) throw domainJSONInvalid();
          const occurrences = new Map<string, number>();
          for (let index = 0; index < req.raw.rawHeaders.length; index += 2) {
            const key = req.raw.rawHeaders[index].toLowerCase(); occurrences.set(key, (occurrences.get(key) ?? 0) + 1);
          }
          if ((occurrences.get('idempotency-key') ?? 0) > 1) throw new Problem(400, 'IDEMPOTENCY_REQUIRED', 'Send one Idempotency-Key.');
          if ((occurrences.get('if-match') ?? 0) > 1) throw new Problem(428, 'VERSION_REQUIRED', 'Send one current version using If-Match.');
          if (spec.expected) state.expected = domainExpectedVersion(req, spec.expected === 'placement');
          if (spec.mutation) state.key = domainIdempotencyKey(req);
          if (spec.body) {
            checkDomainData(req.body);
            if (spec.consent && req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
              const submitted = req.body as Record<string, unknown>;
              const declared = Object.keys(spec.body.properties ?? {});
              if (Object.keys(submitted).every(key => declared.includes(key)) &&
                  (!Object.hasOwn(submitted, 'previewDigest') || typeof submitted.previewDigest !== 'string' || !/^[a-f0-9]{64}$/.test(submitted.previewDigest))) throw previewRequired();
            }
            if (!domainSchemaCheck(spec.body, req.body)) throw domainJSONInvalid();
            if (spec.hierarchy) {
              const { change } = body<DomainHierarchyPreviewRequest>(req);
              if (change.domainId !== id(req) || change.expectedVersion !== state.expected) throw domainJSONInvalid();
            }
          } else if (req.body !== undefined) throw domainJSONInvalid();
        },
        preSerialization: async (_req, reply, value) => {
          if (reply.statusCode < 400 && !domainSchemaCheck(spec.response, value))
            throw new Problem(500, 'DOMAIN_STORAGE_INVALID', 'The domain response did not match its declared contract.');
          return value;
        },
        handler: async (req, reply) => {
          const { principal } = current(req);
          try {
            const result = await scope(principal.tenantId, principal.id, tx => domainQuery(tx, async () => {
              const value = await work(req, tx, principal);
              // Validate before committing canonical writes and idempotency success;
              // serialization also checks the exact egress shape defensively.
              if (!domainSchemaCheck(spec.response, value)) throw new Problem(500, 'DOMAIN_STORAGE_INVALID', 'The domain response did not match its declared contract.');
              return value;
            }));
            reply.code(status);
            // ETags describe only the resource returned by this subresource.
            const value = result as { domain?: { version: number } | null; type?: { version: number }; placement?: { version: number } };
            const resourceVersion = value.placement?.version ?? value.domain?.version ?? value.type?.version;
            if (resourceVersion !== undefined) reply.header('ETag', String(resourceVersion));
            return result;
          } catch (error) { throw domainFailure(error); }
        },
      });
    }

    route('GET', '/domain-types', { query: pageFields, response: domainHttp.response.typePage },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain-types', page: page<DomainPageQuery>(req) }));
    route('POST', '/domain-types/validate', { body: domainHttp.request.file, response: domainHttp.response.definition }, async (req, tx, p) => {
      await authorizeDomain(tx, p, ['models:read']);
      const result = parseDomainTypeFile(body<DomainFileValidationRequest>(req).text);
      if (!result.ok) throw new Problem(422, 'DOMAIN_TYPE_INVALID', 'Correct the domain-type definition file.', result.issues);
      return { definition: result.value };
    });
    route('POST', '/domain-types/migration-plans/validate', { body: domainHttp.request.file, response: domainHttp.response.plan }, async (req, tx, p) => {
      await authorizeDomain(tx, p, ['models:read']);
      const result = parseDomainTypeMigrationFile(body<DomainFileValidationRequest>(req).text);
      if (!result.ok) throw new Problem(422, 'DOMAIN_MIGRATION_INVALID', 'Correct the domain-type migration plan.', result.issues);
      return { plan: result.value };
    });
    route('POST', '/domain-types', { body: domainHttp.request.definition, response: domainHttp.response.type, mutation: true, created: true },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain-type.create', ...body<DomainTypeDefinitionRequest>(req) }));
    route('GET', '/domain-types/:typeId', { params: ['typeId'], response: domainHttp.response.type },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain-type', typeId: typeId(req) }));
    route('GET', '/domain-types/:typeId/versions/:version', { params: ['typeId', 'version'], response: domainHttp.response.type },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain-type', typeId: typeId(req), version: Number((req.params as { version: string }).version) }));
    route('POST', '/domain-types/:typeId/previews', { params: ['typeId'], body: domainHttp.request.definition, response: domainHttp.response.typePreview, expected: 'positive' },
      (req, tx, p) => domainPreview(tx, p, { kind: 'domain-type', typeId: typeId(req), expectedHeadVersion: expected(req), ...body<DomainTypeDefinitionRequest>(req) }));
    route('POST', '/domain-types/:typeId/versions', { params: ['typeId'], body: domainHttp.request.publication, response: domainHttp.response.type, expected: 'positive', mutation: true, created: true, consent: true },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain-type.publish', typeId: typeId(req), expectedHeadVersion: expected(req), ...body<DomainTypePublicationRequest>(req) }));
    route('GET', '/domain-types/:typeId/migration-context', { params: ['typeId'], response: domainHttp.response.migrationContext },
      (req, tx, p) => domainRead(tx, p, { kind: 'migration-context', typeId: typeId(req) }));
    route('POST', '/domain-types/:typeId/migration-previews', { params: ['typeId'], body: domainHttp.request.migrationPreview, response: domainHttp.response.typePreview, expected: 'positive' },
      (req, tx, p) => domainPreview(tx, p, { kind: 'migration', typeId: typeId(req), expectedHeadVersion: expected(req), ...body<DomainTypeMigrationPreviewRequest>(req) }));
    route('POST', '/domain-types/:typeId/migrations', { params: ['typeId'], body: domainHttp.request.migration, response: domainHttp.response.migration, expected: 'positive', mutation: true, created: true, consent: true },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain-type-migration.execute', typeId: typeId(req), expectedHeadVersion: expected(req), ...body<DomainTypeMigrationRequest>(req) }));
    route('GET', '/domain-types/:typeId/migrations/:id', { params: ['typeId', 'id'], response: domainHttp.response.receipt },
      (req, tx, p) => domainRead(tx, p, { kind: 'migration-receipt', typeId: typeId(req), id: id(req) }));

    route('GET', '/domains', { query: [...pageFields, 'parentId', 'status'], response: domainHttp.response.domainPage },
      (req, tx, p) => domainRead(tx, p, { kind: 'domains', page: page<DomainInventoryQuery>(req) }));
    // Register this literal path before UUID resource routes.
    route('GET', '/domains/owner-candidates', { query: pageFields, response: domainHttp.response.ownerPage },
      (req, tx, p) => domainRead(tx, p, { kind: 'owner-candidates', page: page<DomainPageQuery>(req) }));
    route('POST', '/domains', { body: domainHttp.request.create, response: domainHttp.response.domain, mutation: true, created: true },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain.create', ...body<DomainCreateRequest>(req) }));
    route('GET', '/domains/:id', { params: ['id'], response: domainHttp.response.domain },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain', id: id(req) }));
    route('PATCH', '/domains/:id', { params: ['id'], body: domainHttp.request.edit, response: domainHttp.response.domain, mutation: true, expected: 'positive' },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain.update', domainId: id(req), expectedVersion: expected(req), ...body<DomainEditRequest>(req) }));
    route('POST', '/domains/:id/state', { params: ['id'], body: domainHttp.request.state, response: domainHttp.response.domain, mutation: true, expected: 'positive' },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain.state', domainId: id(req), expectedVersion: expected(req), ...body<DomainStateRequest>(req) }));
    route('POST', '/domains/:id/hierarchy-previews', { params: ['id'], body: domainHttp.request.hierarchyPreview, response: domainHttp.response.hierarchyPreview, expected: 'positive', hierarchy: true },
      (req, tx, p) => domainPreview(tx, p, { kind: 'hierarchy', ...body<DomainHierarchyPreviewRequest>(req) }));
    route('POST', '/domains/:id/hierarchy-changes', { params: ['id'], body: domainHttp.request.hierarchy, response: domainHttp.response.domain, mutation: true, expected: 'positive', consent: true, hierarchy: true },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain.hierarchy', ...body<DomainHierarchyRequest>(req) }));
    route('GET', '/domains/:id/history', { params: ['id'], query: historyFields, response: domainHttp.response.history },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain-history', id: id(req), page: page<DomainHistoryQuery>(req) }));
    route('GET', '/domains/:id/assets', { params: ['id'], query: historyFields, response: domainHttp.response.assets },
      (req, tx, p) => domainRead(tx, p, { kind: 'domain-assets', id: id(req), page: page<DomainHistoryQuery>(req) }));
    route('GET', '/assets/:id/domain-placement', { params: ['id'], response: domainHttp.response.placement },
      (req, tx, p) => domainRead(tx, p, { kind: 'placement', assetId: id(req) }));
    route('PUT', '/assets/:id/domain-placement', { params: ['id'], body: domainHttp.request.placement, response: domainHttp.response.placement, mutation: true, expected: 'placement' },
      (req, tx, p) => mutate(req, tx, p, { kind: 'domain.placement', assetId: id(req), expectedPlacementVersion: expected(req), ...body<DomainPlacementRequest>(req) }));
    route('GET', '/assets/:id/domain-placement/history', { params: ['id'], query: historyFields, response: domainHttp.response.placementHistory },
      (req, tx, p) => domainRead(tx, p, { kind: 'placement-history', assetId: id(req), page: page<DomainHistoryQuery>(req) }));
  });
}
